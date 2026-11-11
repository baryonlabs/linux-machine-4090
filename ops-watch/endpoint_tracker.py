#!/usr/bin/env python3
"""User endpoint (PC name & OS) tracker and anomaly detector for ops-watch.

Tracks client machine name, OS, and Tailnet IP per user.
When a user connects from a different PC or changes OS:
1. Generates an approval ticket in ops-watch.db
2. Triggers Antigravity AI analysis
3. Sends notifications (Discord webhook + Web Console notification)
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import sqlite3
import subprocess
import time
from typing import Any, Dict, List, Optional, Tuple

ROOT_DIR = pathlib.Path(__file__).parent
DB_PATH = ROOT_DIR / "state" / "ops-watch.db"
BASE_DIR = ROOT_DIR.parent
DISCORD_WEBHOOK_FILE = pathlib.Path("/etc/labops/discord-webhook.url")


def detect_os(machine_name: str, given_name: str = "") -> str:
    """Infer client operating system from machine hostname and metadata."""
    # Normalize non-breaking spaces and casing
    clean_name = machine_name.replace("\xa0", " ").strip()
    combined = f"{clean_name} {given_name}".lower()
    if any(k in combined for k in ["macbook", "mac mini", "imac", "darwin", "macos", "apple"]):
        return "macOS"
    if any(k in combined for k in ["desktop-", "laptop-", "windows", "win10", "win11", "surface"]):
        return "Windows"
    if any(k in combined for k in ["ubuntu", "debian", "linux", "arch", "fedora", "nucbox", "b300", "b650m"]):
        return "Linux"
    if "노트북" in clean_name or "pc" in combined:
        return "Windows/PC"
    return "Linux/Other"


def get_headscale_nodes() -> List[Dict[str, Any]]:
    """Fetch live nodes from Headscale via local docker or remote ssh linux-builder."""
    cmd = ["ssh", "-o", "ConnectTimeout=4", "linux-builder", "docker exec headscale headscale nodes list -o json"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
        if r.returncode == 0 and r.stdout.strip():
            return json.loads(r.stdout.strip())
    except Exception:
        pass

    # Check local docker if running on same host
    try:
        r = subprocess.run(["docker", "exec", "headscale", "headscale", "nodes", "list", "-o", "json"],
                           capture_output=True, text=True, timeout=5)
        if r.returncode == 0 and r.stdout.strip():
            return json.loads(r.stdout.strip())
    except Exception:
        pass

    return []


# Extra device columns captured from Headscale host_info (added 2026-11-11).
ENDPOINT_EXTRA_COLUMNS = (
    ("os_source", "TEXT"),       # headscale | hostname-guess
    ("os_version", "TEXT"),
    ("distro", "TEXT"),
    ("distro_version", "TEXT"),
    ("arch", "TEXT"),
    ("device_model", "TEXT"),
    ("client_version", "TEXT"),
    ("host_json", "TEXT"),       # full host_info (log/machine IDs stripped)
)


def init_db(c: sqlite3.Connection) -> None:
    c.execute(
        """CREATE TABLE IF NOT EXISTS user_endpoints (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            machine_name TEXT NOT NULL,
            given_name TEXT,
            os_name TEXT,
            ip_address TEXT,
            first_seen INTEGER,
            last_seen INTEGER,
            is_baseline INTEGER DEFAULT 1,
            UNIQUE(username, machine_name)
        )"""
    )
    existing = {row[1] for row in c.execute("PRAGMA table_info(user_endpoints)")}
    for name, col_type in ENDPOINT_EXTRA_COLUMNS:
        if name not in existing:
            c.execute(f"ALTER TABLE user_endpoints ADD COLUMN {name} {col_type}")
    c.commit()


def send_notification(title: str, message: str) -> None:
    """Send notification to Discord webhook if configured."""
    print(f"[NOTIFICATION] {title}: {message}")
    if DISCORD_WEBHOOK_FILE.exists():
        try:
            url = DISCORD_WEBHOOK_FILE.read_text().strip()
            if url.startswith("http"):
                import urllib.request
                data = json.dumps({"content": f"🚨 **[OPS-WATCH] {title}**\n{message}"}).encode("utf-8")
                req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
                urllib.request.urlopen(req, timeout=5)
        except Exception as e:
            print(f"Failed to send Discord webhook: {e}")


def check_and_update_endpoints() -> List[Dict[str, Any]]:
    """Scan current nodes, compare against baseline endpoints, and flag changes."""
    ROOT_DIR.mkdir(parents=True, exist_ok=True)
    (ROOT_DIR / "state").mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(DB_PATH)
    init_db(c)

    nodes = get_headscale_nodes()
    alerts: List[Dict[str, Any]] = []
    now = int(time.time())

    # Real OS / hardware details (Headscale host_info). Falls back to the
    # hostname heuristic when the node has not reported host_info yet.
    try:
        from headscale_monitor import get_host_info_map, summarize_host_info
        hi_map = get_host_info_map()
    except Exception:
        hi_map, summarize_host_info = {}, None

    for n in nodes:
        user_obj = n.get("user", {})
        username = user_obj.get("name") if isinstance(user_obj, dict) else str(user_obj)
        if not username:
            continue

        machine_name = n.get("name", "Unknown PC")
        given_name = n.get("given_name", "")
        ip_list = n.get("ip_addresses", [])
        ip_addr = next((ip for ip in ip_list if "." in ip), ip_list[0] if ip_list else "unknown")

        detail = summarize_host_info(hi_map.get(ip_addr) or {}) if summarize_host_info else {}
        if detail.get("os_label"):
            os_name = detail["os_label"]
            os_source = "headscale"
        else:
            os_name = detect_os(machine_name, given_name)
            os_source = "hostname-guess"
        os_version = detail.get("os_version")
        distro = detail.get("distro")
        distro_version = detail.get("distro_version")
        arch = detail.get("arch")
        device_model = detail.get("device_model")
        client_version = detail.get("client_version")
        host_json = json.dumps(detail.get("raw") or {}, ensure_ascii=False) if detail else None
        is_online = n.get("online", False)

        # Lookup existing baselines for this user
        existing_rows = c.execute(
            "SELECT machine_name, os_name, ip_address, first_seen, last_seen, is_baseline FROM user_endpoints WHERE username=?",
            (username,)
        ).fetchall()

        known_machines = {r[0]: {"os": r[1], "ip": r[2]} for r in existing_rows}

        if machine_name in known_machines:
            # Existing machine - update last_seen and verify OS
            c.execute(
                """UPDATE user_endpoints
                      SET last_seen=?, os_name=?, ip_address=?, os_source=?,
                          os_version=?, distro=?, distro_version=?, arch=?,
                          device_model=?, client_version=?, host_json=?
                    WHERE username=? AND machine_name=?""",
                (now, os_name, ip_addr, os_source, os_version, distro, distro_version,
                 arch, device_model, client_version, host_json, username, machine_name)
            )
            # Check if OS suddenly changed on same machine name
            old_os = known_machines[machine_name]["os"]
            if old_os and old_os != os_name and old_os != "Unknown/Other":
                alert_text = (f"사용자 '{username}'의 PC '{machine_name}' 운영체제(OS) 변경 감지: "
                              f"이전 OS='{old_os}' → 현재 OS='{os_name}' (IP: {ip_addr})")
                alerts.append({
                    "username": username,
                    "machine_name": machine_name,
                    "os_name": os_name,
                    "type": "os_changed",
                    "detail": alert_text
                })
        else:
            # Completely new machine name for this user!
            if existing_rows and username != "martin":
                # Student user changed their baseline machine!
                prev_names = ", ".join(f"'{r[0]}' ({r[1]})" for r in existing_rows)
                alert_text = (f"사용자 '{username}'의 접속 PC 변경 감지: 신규 단말='{machine_name}' (OS: {os_name}, IP: {ip_addr}). "
                              f"기존 베이스라인 단말: {prev_names}")
                
                # Check for suspicious indicator (e.g. PPID or third party name)
                is_critical = any(k in machine_name.lower() for k in ["ppid", "조용우", "unknown", "vm", "test"])
                severity = "critical" if is_critical else "warning"

                c.execute(
                    """INSERT INTO user_endpoints(
                           username, machine_name, given_name, os_name, ip_address,
                           first_seen, last_seen, is_baseline, os_source, os_version,
                           distro, distro_version, arch, device_model, client_version, host_json)
                       VALUES(?,?,?,?,?,?,?,0,?,?,?,?,?,?,?,?)""",
                    (username, machine_name, given_name, os_name, ip_addr, now, now,
                     os_source, os_version, distro, distro_version, arch, device_model,
                     client_version, host_json)
                )

                # Create security ticket in ops-watch tickets table
                fp = hashlib.sha256(f"endpoint_change_{username}_{machine_name}_{now}".encode()).hexdigest()
                action_prop = f"reissue-headscale-{username}" if username == "student1" else "collect-evidence"
                c.execute(
                    "INSERT INTO tickets(created, category, evidence, action, fingerprint, status) VALUES(?,?,?,?,?, 'pending')",
                    (now, "endpoint", alert_text, action_prop, fp)
                )
                tid = c.execute("SELECT id FROM tickets WHERE fingerprint=?", (fp,)).fetchone()[0]

                # Record into worklog
                c.execute(
                    "INSERT INTO worklog(created, ticket_id, kind, body, tags) VALUES(?,?,?,?,?)",
                    (now, tid, "endpoint-alert", f"[{severity.upper()}] {alert_text}", "endpoint,device-change")
                )

                send_notification("사용자 접속 PC 변경 감지", alert_text)

                alerts.append({
                    "ticket_id": tid,
                    "username": username,
                    "machine_name": machine_name,
                    "os_name": os_name,
                    "type": "new_pc_detected",
                    "severity": severity,
                    "detail": alert_text
                })
            else:
                # First time seeing this user - set as initial baseline
                c.execute(
                    """INSERT INTO user_endpoints(
                           username, machine_name, given_name, os_name, ip_address,
                           first_seen, last_seen, is_baseline, os_source, os_version,
                           distro, distro_version, arch, device_model, client_version, host_json)
                       VALUES(?,?,?,?,?,?,?,1,?,?,?,?,?,?,?,?)""",
                    (username, machine_name, given_name, os_name, ip_addr, now, now,
                     os_source, os_version, distro, distro_version, arch, device_model,
                     client_version, host_json)
                )

    c.commit()
    c.close()
    return alerts


def get_all_user_endpoints() -> List[Dict[str, Any]]:
    """Return all recorded user endpoints with OS, IP, and baseline status."""
    if not DB_PATH.exists():
        return []
    c = sqlite3.connect(DB_PATH)
    init_db(c)
    rows = c.execute(
        """SELECT username, machine_name, given_name, os_name, ip_address,
                  datetime(first_seen,'unixepoch','localtime'),
                  datetime(last_seen,'unixepoch','localtime'),
                  is_baseline, os_source, os_version, distro, distro_version,
                  arch, device_model, client_version
           FROM user_endpoints ORDER BY username, last_seen DESC"""
    ).fetchall()
    c.close()

    res = []
    for r in rows:
        detail = " ".join(str(p) for p in (r[3], r[9]) if p).strip()  # os_name + os_version
        if r[10] and r[11]:
            detail = f"{detail} · {r[10]} {r[11]}".strip(" ·")
        extra = [x for x in (r[12], r[13]) if x]  # arch, device_model
        if extra:
            detail = f"{detail} ({', '.join(extra)})" if detail else " / ".join(extra)
        res.append({
            "username": r[0],
            "machine_name": r[1],
            "given_name": r[2],
            "os_name": r[3],
            "ip_address": r[4],
            "first_seen": r[5],
            "last_seen": r[6],
            "is_baseline": bool(r[7]),
            "os_source": r[8],
            "os_version": r[9],
            "distro": r[10],
            "distro_version": r[11],
            "arch": r[12],
            "device_model": r[13],
            "client_version": r[14],
            "os_detail": detail,
        })
    return res


if __name__ == "__main__":
    print("Checking Headscale user endpoints...")
    alerts = check_and_update_endpoints()
    print(f"Detected {len(alerts)} endpoint alert(s).")
    endpoints = get_all_user_endpoints()
    print(f"Recorded endpoints ({len(endpoints)}):")
    for ep in endpoints:
        print(f" - {ep['username']}: {ep['machine_name']} [OS: {ep['os_name']}, IP: {ep['ip_address']}] (Baseline: {ep['is_baseline']})")
