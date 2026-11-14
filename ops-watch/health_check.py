#!/usr/bin/env python3
"""OPS-WATCH SSH Reachability Watchdog.

Why this exists
---------------
`tailscale ping` is answered by the *tailscaled process*, not by the kernel data
plane. On 2026-11-11 the GPU host answered tailscale ping (direct, 5 ms) while
every TCP port on 100.64.0.2 (2322, 22, 8888, ...) timed out because a host
firewall was dropping NEW inbound connections. Ping-only monitoring reported
"healthy" for hours.

This module probes the real thing: a TCP connect to sshd plus the SSH banner.
It classifies the failure, keeps a last-OK timestamp, and alerts Discord once
per state transition (outage and recovery).

Outputs
-------
    python3 health_check.py            # human readable
    python3 health_check.py --json     # machine readable
    python3 health_check.py --alert    # run one cycle + send webhook if changed

Used by dashboard.py (/api/health/ssh and a background watchdog).
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import threading
import time
from typing import Any, Dict, List, Optional

BASE_DIR = pathlib.Path(__file__).parent.resolve()
STATE_DIR = BASE_DIR / "state"
STATE_FILE = STATE_DIR / "ssh_health.json"

# Targets. Override with env vars on the dashboard host.
SSH_HOST = os.environ.get("OPS_WATCH_SSH_HOST", "100.64.0.2")
SSH_PORT = int(os.environ.get("OPS_WATCH_SSH_PORT", "2322"))
# LAN probe is disabled by default: the dashboard usually runs off-LAN (admin Mac),
# where a LAN timeout says nothing about the host. Enable it on an on-site machine:
#   OPS_WATCH_LAN_HOST=192.168.219.45
LAN_HOST = os.environ.get("OPS_WATCH_LAN_HOST", "")
SEGMENT_HOST = os.environ.get("OPS_WATCH_SEGMENT_HOST", "")  # optional extra probe

PROBE_TIMEOUT = float(os.environ.get("OPS_WATCH_PROBE_TIMEOUT", "4.0"))
# A single 3-4s timeout can be a tailnet path switch (DERP <-> direct, NAT rebind).
# Require this many consecutive failed checks before alerting.
ALERT_AFTER = int(os.environ.get("OPS_WATCH_HEALTH_ALERT_AFTER", "2"))
CACHE_TTL = float(os.environ.get("OPS_WATCH_HEALTH_TTL", "20"))

# States
OK = "OK"
DEGRADED = "DEGRADED"                 # port accepts, but no SSH banner
FIREWALL_BLOCKED = "FIREWALL_BLOCKED" # tailscaled answers, TCP dropped
LISTENER_DOWN = "LISTENER_DOWN"       # TCP RST -> host up, sshd not listening
HOST_UNREACHABLE = "HOST_UNREACHABLE" # nothing answers at all
TAILNET_ONLY = "TAILNET_ONLY"         # tailnet fine, LAN blocked

_state_lock = threading.Lock()
_cache: Dict[str, Any] = {"ts": 0.0, "result": None}


# --------------------------------------------------------------------------- #
# probes
# --------------------------------------------------------------------------- #
def tcp_probe(host: str, port: int, timeout: float = PROBE_TIMEOUT,
              read_banner: bool = True) -> Dict[str, Any]:
    """TCP connect (+ optional SSH banner read). Distinguishes DROP vs RST."""
    if not host:
        return {"ok": False, "state": "SKIPPED", "error": "no host"}

    started = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            latency_ms = round((time.monotonic() - started) * 1000, 1)
            banner = ""
            if read_banner:
                sock.settimeout(min(2.0, timeout))
                try:
                    banner = sock.recv(255).decode("utf-8", "replace").strip()
                except Exception:
                    banner = ""
            return {
                "ok": True,
                "state": "OPEN",
                "latency_ms": latency_ms,
                "banner": banner,
                "sshd": banner.startswith("SSH-"),
            }
    except ConnectionRefusedError as exc:
        return {"ok": False, "state": "REFUSED", "error": str(exc),
                "latency_ms": round((time.monotonic() - started) * 1000, 1)}
    except socket.timeout:
        return {"ok": False, "state": "TIMEOUT", "error": "timed out",
                "latency_ms": round((time.monotonic() - started) * 1000, 1)}
    except OSError as exc:
        return {"ok": False, "state": "ERROR", "error": f"{type(exc).__name__}: {exc}",
                "latency_ms": round((time.monotonic() - started) * 1000, 1)}


def _tailscale_exe() -> Optional[str]:
    for candidate in (
        shutil.which("tailscale"),
        "/Applications/Tailscale.app/Contents/MacOS/Tailscale",
        "/usr/bin/tailscale",
        "/usr/local/bin/tailscale",
    ):
        if candidate and pathlib.Path(candidate).exists():
            return candidate
    return None


def tailscale_peer(ip: str = SSH_HOST) -> Optional[Dict[str, Any]]:
    """Peer state straight from tailscaled (works even when TCP is blocked)."""
    exe = _tailscale_exe()
    if not exe:
        return None
    try:
        proc = subprocess.run([exe, "status", "--json"], capture_output=True,
                              text=True, timeout=10)
        data = json.loads(proc.stdout or "{}")
    except Exception:
        return None

    for peer in (data.get("Peer") or {}).values():
        if ip in (peer.get("TailscaleIPs") or []):
            last_seen = peer.get("LastSeen")
            return {
                "host": peer.get("HostName"),
                "online": bool(peer.get("Online")),
                "active": bool(peer.get("Active")),
                "os": peer.get("OS"),
                "last_seen": last_seen,
                "ssh_enabled": bool(peer.get("TailscaleSSHEnabled")),
            }
    return None


# --------------------------------------------------------------------------- #
# classification
# --------------------------------------------------------------------------- #
def _classify(tailnet: Dict[str, Any], lan: Dict[str, Any],
              peer: Optional[Dict[str, Any]]) -> str:
    if tailnet.get("ok") and tailnet.get("sshd"):
        return OK
    if tailnet.get("ok"):
        return DEGRADED
    if tailnet.get("state") == "REFUSED":
        return LISTENER_DOWN
    peer_online = bool(peer and (peer.get("online") or peer.get("active")))
    if peer_online:
        # tailscaled answers/disco works, but kernel TCP is dropped.
        return FIREWALL_BLOCKED
    if lan.get("ok"):
        return TAILNET_ONLY
    if lan.get("state") == "REFUSED":
        return LISTENER_DOWN
    return HOST_UNREACHABLE


def _load_state() -> Dict[str, Any]:
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_state(state: Dict[str, Any]) -> None:
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(json.dumps(state, ensure_ascii=False, indent=1),
                              encoding="utf-8")
    except Exception as exc:  # never break the dashboard on a write error
        print(f"[health] state write failed: {exc}", file=sys.stderr)


def get_ssh_health(force: bool = False) -> Dict[str, Any]:
    """Cached reachability snapshot used by the dashboard."""
    with _state_lock:
        if not force and _cache["result"] and (time.time() - _cache["ts"]) < CACHE_TTL:
            return _cache["result"]

        peer = tailscale_peer(SSH_HOST)
        tailnet = tcp_probe(SSH_HOST, SSH_PORT)
        if not tailnet.get("ok"):
            # one retry: path renegotiation (DERP <-> direct) can drop a single SYN
            time.sleep(1.2)
            retry = tcp_probe(SSH_HOST, SSH_PORT)
            if retry.get("ok"):
                retry["retried"] = True
                tailnet = retry
        lan = tcp_probe(LAN_HOST, SSH_PORT) if LAN_HOST else {"ok": False, "state": "SKIPPED"}
        segment = tcp_probe(SEGMENT_HOST, SSH_PORT) if SEGMENT_HOST else None

        state = _classify(tailnet, lan, peer)
        now = int(time.time())

        prev = _load_state()
        last_ok = prev.get("last_ok") if state != OK else now
        if state == OK:
            last_ok = now
        since = prev.get("since") if prev.get("last_state") == state and prev.get("since") else now
        fail_count = 0 if state == OK else int(prev.get("fail_count") or 0) + 1

        result = {
            "state": state,
            "ok": state == OK,
            "checked_at": now,
            "checked_at_str": datetime.datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S"),
            "since": since,
            "since_str": datetime.datetime.fromtimestamp(since).strftime("%Y-%m-%d %H:%M:%S"),
            "last_ok": last_ok,
            "last_ok_str": datetime.datetime.fromtimestamp(last_ok).strftime("%Y-%m-%d %H:%M:%S") if last_ok else None,
            "outage_seconds": (now - last_ok) if (last_ok and state != OK) else 0,
            "fail_count": fail_count,
            "tailscale_peer": peer,
            "probes": {"tailnet": {"target": f"{SSH_HOST}:{SSH_PORT}", **tailnet}},
        }
        if LAN_HOST:
            result["probes"]["lan"] = {"target": f"{LAN_HOST}:{SSH_PORT}", **lan}
        if segment:
            result["probes"]["segment"] = {"target": f"{SEGMENT_HOST}:{SSH_PORT}", **segment}

        _save_state({
            "last_state": state, "since": since, "last_ok": last_ok,
            "fail_count": fail_count, "last_alerted": prev.get("last_alerted"),
            "checked_at": now,
        })
        _cache["ts"] = time.time()
        _cache["result"] = result
        return result


# --------------------------------------------------------------------------- #
# discord alerting (one message per transition)
# --------------------------------------------------------------------------- #
_TITLES = {
    OK: ("🟢 [martin-B650M-K] SSH 2322 복구됨", 0x2ECC71),
    DEGRADED: ("🟠 [martin-B650M-K] SSH 포트는 열렸지만 배너 없음", 0xF39C12),
    FIREWALL_BLOCKED: ("🛑 [martin-B650M-K] SSH 2322 차단 (방화벽 의심)", 0xE74C3C),
    LISTENER_DOWN: ("🛑 [martin-B650M-K] sshd 미기동 (포트 거부)", 0xE74C3C),
    HOST_UNREACHABLE: ("🔴 [martin-B650M-K] 호스트 도달 불가", 0xE74C3C),
    TAILNET_ONLY: ("🟠 [martin-B650M-K] LAN에서만 SSH 차단", 0xF39C12),
}

_HINTS = {
    DEGRADED: "포트는 열리는데 SSH 배너가 없습니다. sshd 행(hang)·과부하·다른 프로세스 점유를 확인하세요.",
    FIREWALL_BLOCKED: (
        "tailscaled는 응답하지만 커널 TCP가 타임아웃되었습니다.\n"
        "DERP↔direct 경로 전환·NAT 재바인딩 순간에도 같은 증상이 1회 발생할 수 있어,\n"
        "2회 연속 실패일 때만 알림을 보냅니다. 지속되면 호스트에서 `sudo ufw status verbose`,\n"
        "`sudo nft list ruleset`, `sudo iptables -S`를 확인하세요."
    ),
    LISTENER_DOWN: "TCP가 RST로 거부됩니다. 호스트는 살아 있으나 sshd가 2322에 리스닝하지 않습니다. `sudo systemctl restart ssh`.",
    HOST_UNREACHABLE: "ping/TCP 모두 무응답입니다. 전원·네트워크 케이블·공유기를 확인하세요.",
    TAILNET_ONLY: "VPN 경로는 정상, 같은 LAN에서만 차단되었습니다. ufw 인터페이스 규칙(enp6s0)을 확인하세요.",
}


def _build_embed(result: Dict[str, Any]) -> Dict[str, Any]:
    title, color = _TITLES.get(result["state"], ("OPS-WATCH SSH 상태", 0x38BDF8))
    probes = result["probes"]
    peer = result.get("tailscale_peer") or {}

    def line(name: str, p: Dict[str, Any]) -> str:
        if p.get("ok"):
            return f"• **{name}** `{p['target']}`: ✅ OPEN {p.get('latency_ms')}ms {p.get('banner','')[:24]}"
        return f"• **{name}** `{p['target']}`: ❌ {p.get('state')} ({p.get('error','')[:40]})"

    fields = [
        {"name": "🔌 프로브", "inline": False,
         "value": "\n".join(line(name, p) for name, p in probes.items())},
        {"name": "🛰️ tailscaled", "inline": True,
         "value": f"online={peer.get('online')} active={peer.get('active')} os={peer.get('os')}"},
        {"name": "⏱️ 마지막 정상", "inline": True,
         "value": f"{result.get('last_ok_str') or '기록 없음'}\n(연속 실패 {result['fail_count']}회)"},
    ]
    hint = _HINTS.get(result["state"])
    description = f"상태: **{result['state']}** · 감지 {result['since_str']}"
    if hint:
        description += f"\n> {hint}"

    return {
        "title": title,
        "description": description,
        "color": color,
        "fields": fields,
        "footer": {"text": "martin-B650M-K LabOps • SSH 도달성 워치독 (TCP 2322)"},
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }


def check_and_alert(force: bool = False) -> Dict[str, Any]:
    """Probe once and notify Discord when the state changes."""
    result = get_ssh_health(force=True)
    state = result["state"]
    prev = _load_state()
    last_alerted = prev.get("last_alerted")

    should_alert = force or (state != last_alerted)
    # debounce: ignore a single transient failure (tailnet path flap)
    if not force and state != OK and result["fail_count"] < ALERT_AFTER:
        should_alert = False
    # Do not spam on the very first observation if everything is fine.
    if last_alerted is None and state == OK:
        should_alert = False

    if should_alert:
        try:
            import gpu_discord_notifier
            webhook = gpu_discord_notifier.get_webhook_url()
            if webhook:
                sent = gpu_discord_notifier.send_discord_webhook(webhook, _build_embed(result))
                if sent:
                    prev["last_alerted"] = state
                    _save_state(prev)
                    result["alerted"] = True
            else:
                result["alerted"] = False
                result["alert_error"] = "no webhook configured"
        except Exception as exc:
            result["alerted"] = False
            result["alert_error"] = str(exc)

    return result


_WATCHDOG_STARTED = False


def start_watchdog(interval: int = 60) -> None:
    """Background daemon: probe every `interval` seconds and alert on change."""
    global _WATCHDOG_STARTED
    if _WATCHDOG_STARTED:
        return
    _WATCHDOG_STARTED = True

    def loop() -> None:
        time.sleep(5)  # let the HTTP server bind first
        while True:
            try:
                check_and_alert()
            except Exception as exc:
                print(f"[health] watchdog error: {exc}", file=sys.stderr)
            time.sleep(max(15, interval))

    threading.Thread(target=loop, name="ssh-health-watchdog", daemon=True).start()


def _render(result: Dict[str, Any]) -> str:
    lines = [
        f"SSH health: {result['state']}  (ok={result['ok']})",
        f"  checked : {result['checked_at_str']}",
        f"  since   : {result['since_str']}",
        f"  last ok : {result['last_ok_str']}",
    ]
    for name, probe in result["probes"].items():
        if probe.get("ok"):
            lines.append(f"  {name:7s} {probe['target']}: OPEN {probe.get('latency_ms')}ms {probe.get('banner','')}")
        else:
            lines.append(f"  {name:7s} {probe['target']}: {probe.get('state')} {probe.get('error','')}")
    peer = result.get("tailscale_peer") or {}
    lines.append(f"  tailscaled peer: online={peer.get('online')} active={peer.get('active')} os={peer.get('os')}")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="OPS-WATCH SSH reachability watchdog")
    parser.add_argument("--json", action="store_true", help="print JSON")
    parser.add_argument("--alert", action="store_true", help="send Discord alert if state changed")
    parser.add_argument("--force-alert", action="store_true", help="send Discord alert regardless")
    args = parser.parse_args()

    result = check_and_alert(force=args.force_alert) if (args.alert or args.force_alert) else get_ssh_health(force=True)

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=1))
    else:
        print(_render(result))
        if result.get("alerted"):
            print("  -> Discord alert sent")
        elif "alert_error" in result:
            print(f"  -> alert skipped: {result['alert_error']}")

    if result["state"] != OK:
        sys.exit(2)


if __name__ == "__main__":
    main()
