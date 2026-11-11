#!/usr/bin/env python3
"""Process Inspector and Anomaly Detector for ops-watch.

Inspects running processes via `ps` and `/proc` on the GPU server:
1. Detects processes executing from unprivileged temporary directories (/tmp, /dev/shm, /var/tmp)
2. Detects processes owned by locked or expired accounts (e.g. student5, student6)
3. Detects deleted binary executions (/proc/*/exe -> (deleted))
4. Detects process masquerading (user processes pretending to be kernel threads like [kworker/...])
5. Detects crypto miners, unauthorized port scanners, or suspicious reverse shells
6. Formats anomalies into ops-watch tickets and web dashboard metrics
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import shlex
import subprocess
import time
from typing import Any, Dict, List, Optional, Tuple

ROOT_DIR = pathlib.Path(__file__).parent
USERS_YAML = ROOT_DIR.parent / "labops" / "users.yaml"

# Suspicious tools when executed by non-admin or student accounts
SUSPICIOUS_COMM_NAMES = {
    "xmrig", "minerd", "cpuminer", "ccminer", "cgminer", "stratum",
    "nmap", "masscan", "zmap", "nikto", "hydra", "aircrack",
    "nc", "ncat", "netcat", "socat"
}

TEMP_DIRS = ("/tmp/", "/dev/shm/", "/var/tmp/")


def get_locked_users() -> set[str]:
    """Retrieve usernames currently marked as 'locked' in users.yaml."""
    locked = set()
    if USERS_YAML.exists():
        try:
            content = USERS_YAML.read_text(encoding="utf-8")
            blocks = content.split("- name:")
            for b in blocks[1:]:
                lines = b.splitlines()
                uname = lines[0].strip()
                if "state: locked" in b or "state: removed" in b:
                    locked.add(uname)
        except Exception:
            pass
    return locked


def run_remote_or_local(cmd_str: str) -> str:
    """Execute command on remote linux-builder or fallback to local system."""
    # Try SSH first if configured
    try:
        r = subprocess.run(
            ["ssh", "-o", "ConnectTimeout=4", "linux-builder", cmd_str],
            capture_output=True, text=True, timeout=8
        )
        if r.returncode == 0:
            return r.stdout
    except Exception:
        pass

    # Fallback to local execution
    try:
        r = subprocess.run(cmd_str, shell=True, capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            return r.stdout
    except Exception:
        pass
    return ""


def fetch_process_list() -> List[Dict[str, Any]]:
    """Fetch structured process list with user, pid, %cpu, %mem, stat, comm, args."""
    # ps command: user:25,pid,pcpu,pmem,stat,comm,args
    raw = run_remote_or_local("ps -eo user:25,pid,%cpu,%mem,stat,comm,args --sort=-%cpu")
    if not raw.strip():
        return []

    lines = raw.strip().splitlines()
    if len(lines) < 2:
        return []

    processes = []
    locked_users = get_locked_users()

    for line in lines[1:]:
        parts = line.split(None, 6)
        if len(parts) < 7:
            continue

        user = parts[0]
        try:
            pid = int(parts[1])
            cpu = float(parts[2])
            mem = float(parts[3])
        except ValueError:
            continue

        stat = parts[4]
        comm = parts[5]
        args = parts[6]

        # Ignore the self-monitoring inspection commands (observer effect)
        if comm == "ps" and "ps -eo" in args:
            continue
        if "ps -eo user:25,pid,%cpu,%mem,stat,comm,args" in args:
            continue
        # Ignore Ops-Watch storage measurement and maintenance tasks run by admin
        if user == "martin" and ("du -s" in args or "nice -n 19" in args) and any(p in args for p in ["/mnt/data", "/home"]):
            continue

        # Anomaly evaluation
        anomalies = []
        severity = "normal"

        # 1. Check if user is locked
        if user in locked_users:
            anomalies.append(f"잠긴(locked) 계정 '{user}'의 프로세스 실행 중")
            severity = "critical"

        # 2. Check if executing from temp directories
        for td in TEMP_DIRS:
            if td in args or td in comm:
                # Whitelist common safe sockets or non-executable args if strictly arguments
                if args.startswith(td) or f" {td}" in args or comm.startswith(td):
                    anomalies.append(f"임시 디렉토리({td}) 바이너리/스크립트 실행 감지")
                    severity = "critical"
                    break

        # 3. Check for suspicious tools
        comm_lower = comm.lower()
        if comm_lower in SUSPICIOUS_COMM_NAMES:
            anomalies.append(f"비인가 보안 진단/터널링/채굴 도구({comm}) 실행")
            severity = "critical"

        # 4. Check for kernel thread masquerading
        if (args.startswith("[kworker") or args.startswith("[ksoftirqd")) and user != "root":
            anomalies.append("커널 스레드 위장(Masquerading) 의심 일반 사용자 프로세스")
            severity = "critical"

        # 5. High CPU utilization by non-root, non-ML command
        if cpu >= 90.0 and user != "root":
            if comm in ("ps", "top", "htop", "glances"):
                pass
            elif comm in ("du", "df", "find", "ionice", "nice") and user == "martin":
                pass
            elif not any(ml in args for ml in ["python", "torch", "sglang", "vllm", "ray", "uv"]):
                anomalies.append(f"비인가 고부하 CPU 점유율({cpu}%)")
                if severity == "normal":
                    severity = "warning"

        processes.append({
            "user": user,
            "pid": pid,
            "cpu": cpu,
            "mem": mem,
            "stat": stat,
            "command": comm,
            "full_command": args[:300],
            "severity": severity,
            "is_anomaly": len(anomalies) > 0,
            "anomaly_reasons": anomalies
        })

    return processes


def scan_deleted_binaries() -> List[Dict[str, Any]]:
    """Scan /proc/*/exe for processes executing deleted binary files."""
    raw = run_remote_or_local("ls -l /proc/*/exe 2>/dev/null | grep -i 'deleted' || true")
    if not raw.strip():
        return []

    results = []
    for line in raw.strip().splitlines():
        # format: lrwxrwxrwx 1 user group 0 date /proc/1234/exe -> /path/to/binary (deleted)
        m = re.search(r"^\S+\s+\d+\s+(\S+)\s+\S+.*?/proc/(\d+)/exe\s*->\s*(.+?)\s*\(deleted\)", line)
        if m:
            user = m.group(1).strip()
            pid = int(m.group(2))
            path = m.group(3).strip()
        else:
            m_alt = re.search(r"/proc/(\d+)/exe\s*->\s*(.+?)\s*\(deleted\)", line)
            if not m_alt:
                continue
            pid = int(m_alt.group(1))
            path = m_alt.group(2).strip()
            user = "unknown"

        # Check if the binary was replaced by a legitimate package manager upgrade (apt/dpkg):
        # e.g., /usr/bin/dbus-daemon, /usr/lib/..., /bin/..., /usr/sbin/...
        # and test if the file path still exists on disk.
        is_pkg_update = False
        is_system_path = any(path.startswith(prefix) for prefix in ("/usr/bin/", "/usr/sbin/", "/usr/lib/", "/bin/", "/sbin/"))
        if is_system_path:
            chk = run_remote_or_local(f"test -f {shlex.quote(path)} && echo 'EXISTS' || true")
            if "EXISTS" in chk:
                is_pkg_update = True

        if is_pkg_update:
            results.append({
                "pid": pid,
                "user": user,
                "deleted_binary": path,
                "severity": "info",
                "is_pkg_upgrade": True,
                "reason": f"패키지 업데이트로 디스크 바이너리 교체됨 (재시작 권장): PID {pid} -> {path} (deleted)"
            })
        else:
            results.append({
                "pid": pid,
                "user": user,
                "deleted_binary": path,
                "severity": "critical",
                "is_pkg_upgrade": False,
                "reason": f"삭제된 바이너리 메모리 실행: PID {pid} -> {path} (deleted)"
            })
    return results


def inspect_anomalies() -> List[Dict[str, Any]]:
    """Run full inspection and return list of actionable security anomalies."""
    anomalies: List[Dict[str, Any]] = []

    # 1. Process list inspection
    procs = fetch_process_list()
    for p in procs:
        if p["is_anomaly"]:
            anomalies.append({
                "type": "process_anomaly",
                "pid": p["pid"],
                "user": p["user"],
                "command": p["full_command"],
                "cpu": p["cpu"],
                "mem": p["mem"],
                "reasons": p["anomaly_reasons"],
                "severity": p["severity"],
                "description": (
                    f"Suspicious process execution (PID {p['pid']} under user '{p['user']}'): "
                    f"{'; '.join(p['anomaly_reasons'])}. CMD: {p['full_command'][:150]}"
                )
            })

    # 2. Deleted binaries inspection
    deleted = scan_deleted_binaries()
    for d in deleted:
        anomalies.append({
            "type": "deleted_binary",
            "pid": d["pid"],
            "user": d.get("user", "unknown"),
            "command": d["deleted_binary"],
            "cpu": 0.0,
            "mem": 0.0,
            "reasons": [d["reason"]],
            "severity": d.get("severity", "critical"),
            "description": (
                f"Package upgrade replaced binary (service restart recommended): {d['reason']}"
                if d.get("is_pkg_upgrade")
                else f"Anomalous execution of deleted binary: {d['reason']}"
            )
        })

    return anomalies


if __name__ == "__main__":
    print("=== RUNNING PROCESS INSPECTION ===")
    procs = fetch_process_list()
    print(f"Total processes fetched: {len(procs)}")
    anomalies = inspect_anomalies()
    print(f"Anomalies found: {len(anomalies)}")
    for a in anomalies:
        print(f"[{a['severity'].upper()}] PID {a['pid']} ({a['user']}): {a['description']}")
