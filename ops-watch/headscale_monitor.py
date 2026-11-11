#!/usr/bin/env python3
"""Headscale VPN management module for Ops-Watch.

Provides live node tracking, user namespace management, pre-auth key generation,
node expiration/deletion, and ACL diagnostics.
"""

from __future__ import annotations

import base64
import json
import logging
import re
import shlex
import subprocess
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger("headscale_monitor")

def run_remote(cmd: str, timeout: int = 10) -> str:
    """Execute command on linux-builder host via SSH."""
    ssh_cmd = ["ssh", "-o", "ConnectTimeout=5", "linux-builder", cmd]
    try:
        r = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception as e:
        logger.error(f"Failed to run remote command: {e}")
        return ""


# --------------------------------------------------------------------------- #
# Detailed device information (Headscale `nodes.host_info`)
#
# `headscale nodes list -o json` omits host_info, but Headscale stores it in its
# SQLite DB. It contains the real OS, OS version, distro, architecture, device
# model, Tailscale client version, network capabilities and TPM info.
# We read it read-only and keep everything except opaque log/machine IDs.
# --------------------------------------------------------------------------- #
HOSTINFO_READER = r'''
import json, sqlite3
c = sqlite3.connect("file:/home/martin/headscale/data/db.sqlite?mode=ro", uri=True)
out = {}
for hostname, ipv4, hi in c.execute(
        "select hostname, ipv4, host_info from nodes where deleted_at is null"):
    try:
        info = json.loads(hi) if hi else {}
    except Exception:
        info = {}
    key = (ipv4 or "").split("/")[0]
    if key:
        out[key] = dict(info, Hostname=hostname)
print(json.dumps(out, ensure_ascii=False))
'''

_OS_LABELS = {
    "macos": ("macOS", "🍎", "#f8fafc"),
    "macosx": ("macOS", "🍎", "#f8fafc"),
    "ios": ("iOS", "📱", "#a5b4fc"),
    "linux": ("Linux", "🐧", "#34d399"),
    "windows": ("Windows", "🪟", "#38bdf8"),
    "android": ("Android", "🤖", "#4ade80"),
}

_SKIP_HOSTINFO_KEYS = ("BackendLogID", "FrontendLogID", "MachineKey", "NodeKey", "DiscoKey")

_info_cache: Dict[str, Any] = {"ts": 0.0, "data": {}}
_HOSTINFO_TTL = 30.0


def get_host_info_map(force: bool = False) -> Dict[str, Dict[str, Any]]:
    """Return {ipv4: host_info} read from Headscale's DB (cached 30s)."""
    now = time.time()
    if not force and _info_cache["data"] and (now - _info_cache["ts"]) < _HOSTINFO_TTL:
        return _info_cache["data"]

    code = base64.b64encode(HOSTINFO_READER.encode()).decode()
    raw = run_remote(f"python3 -c \"import base64;exec(base64.b64decode('{code}').decode())\"", timeout=12)
    if not raw:
        return _info_cache["data"]

    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            _info_cache["data"] = data
            _info_cache["ts"] = now
    except Exception as e:
        logger.error(f"host_info parse failed: {e}")
    return _info_cache["data"]


def summarize_host_info(info: Dict[str, Any]) -> Dict[str, Any]:
    """Flatten the useful (non-sensitive) parts of a Headscale host_info blob."""
    if not info:
        return {}

    clean = {k: v for k, v in info.items() if not any(s in k for s in _SKIP_HOSTINFO_KEYS)}
    net = clean.get("NetInfo") or {}
    tpm = clean.get("TPM") or {}
    os_raw = str(clean.get("OS") or "").lower()
    label, icon, color = _OS_LABELS.get(os_raw, (clean.get("OS") or "", "📟", "#94a3b8"))

    derp_latency = net.get("DERPLatency") or {}
    best_derp = None
    if isinstance(derp_latency, dict) and derp_latency:
        try:
            region, latency = min(derp_latency.items(), key=lambda kv: kv[1])
            best_derp = {"region": region, "ms": round(float(latency) * 1000, 1)}
        except Exception:
            best_derp = None

    return {
        "os_label": label,
        "os_icon": icon,
        "os_color": color,
        "os_version": clean.get("OSVersion"),
        "distro": clean.get("Distro"),
        "distro_version": clean.get("DistroVersion"),
        "distro_codename": clean.get("DistroCodeName"),
        "arch": clean.get("Machine") or clean.get("GoArch"),
        "device_model": clean.get("DeviceModel"),
        "client_version": clean.get("IPNVersion"),
        "package": clean.get("Package"),
        "container": clean.get("Container"),
        "desktop": clean.get("Desktop"),
        "go_version": clean.get("GoVersion"),
        "net": {
            "preferred_derp": net.get("PreferredDERP"),
            "best_derp": best_derp,
            "udp": net.get("WorkingUDP"),
            "ipv6": net.get("WorkingIPv6"),
            "portmap": net.get("HavePortMap"),
            "firewall_mode": net.get("FirewallMode"),
            "mapping_varies": net.get("MappingVariesByDestIP"),
        },
        "tpm": ({k: tpm.get(k) for k in ("Manufacturer", "Vendor", "Model", "SpecRevision")}
                if tpm else None),
        "raw": clean,
    }


def format_os_detail(detail: Dict[str, Any]) -> str:
    """Human readable one-liner: 'macOS 26.7.1 · arm64 · Mac16,8'."""
    if not detail:
        return ""
    parts = []
    head = detail.get("os_label") or ""
    if detail.get("distro") and detail.get("distro_version"):
        head = f"{head} {detail['distro']} {detail['distro_version']}".strip()
    if detail.get("os_version"):
        head = f"{head} {detail['os_version']}".strip()
    if head:
        parts.append(head)
    if detail.get("arch"):
        parts.append(detail["arch"])
    if detail.get("device_model"):
        parts.append(detail["device_model"])
    return " · ".join(parts)


def detect_os(machine_name: str, given_name: str = "") -> Dict[str, str]:
    """Infer client operating system and display icon/badge."""
    clean_name = machine_name.replace("\xa0", " ").strip()
    combined = f"{clean_name} {given_name}".lower()

    if any(k in combined for k in ["macbook", "mac mini", "imac", "darwin", "macos", "apple"]):
        return {"os": "macOS", "icon": "🍎", "color": "#f8fafc"}
    if any(k in combined for k in ["desktop-", "laptop-", "windows", "win10", "win11", "surface"]):
        return {"os": "Windows", "icon": "🪟", "color": "#38bdf8"}
    if any(k in combined for k in ["ubuntu", "debian", "linux", "arch", "fedora", "nucbox", "b300", "b650m"]):
        return {"os": "Linux", "icon": "🐧", "color": "#34d399"}
    if "노트북" in clean_name or "pc" in combined:
        return {"os": "Windows/PC", "icon": "💻", "color": "#a5b4fc"}
    return {"os": "Unknown", "icon": "📟", "color": "#94a3b8"}


def format_ts(ts_obj: Any) -> str:
    """Convert Headscale protobuf timestamp {seconds, nanos} to formatted string."""
    if not ts_obj:
        return "-"
    if isinstance(ts_obj, dict):
        sec = ts_obj.get("seconds", 0)
    elif isinstance(ts_obj, (int, float)):
        sec = int(ts_obj)
    elif isinstance(ts_obj, str):
        try:
            return ts_obj.split("T")[0] + " " + ts_obj.split("T")[1][:8]
        except Exception:
            return ts_obj
    else:
        return "-"

    if sec == 0 or sec < 1000000000:
        return "-"
    try:
        dt = datetime.fromtimestamp(sec)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "-"


def format_relative(sec: int) -> str:
    """Format seconds into human-readable relative duration."""
    if not sec or sec <= 0:
        return "-"
    now = int(time.time())
    diff = now - sec
    if diff < 0:
        return "미래"
    if diff < 60:
        return f"{diff}초 전"
    if diff < 3600:
        return f"{diff // 60}분 전"
    if diff < 86400:
        return f"{diff // 3600}시간 전"
    return f"{diff // 86400}일 전"


def get_headscale_nodes() -> List[Dict[str, Any]]:
    """Retrieve full list of registered Headscale nodes."""
    raw = run_remote("docker exec headscale headscale nodes list -o json")
    if not raw:
        return []
    try:
        nodes = json.loads(raw)
        results = []
        now = int(time.time())
        hi_map = get_host_info_map()
        for n in nodes:
            nid = n.get("id")
            name = n.get("name", "Unknown Node")
            given_name = n.get("given_name", "")
            u_obj = n.get("user", {})
            user_name = u_obj.get("name") if isinstance(u_obj, dict) else str(u_obj)
            ips = n.get("ip_addresses", [])
            ipv4 = next((ip for ip in ips if "." in ip), "-")
            ipv6 = next((ip for ip in ips if ":" in ip), "-")
            online = bool(n.get("online", False))

            hi = hi_map.get(ipv4) or {}
            detail = summarize_host_info(hi)
            if detail.get("os_label"):
                os_info = {"os": detail["os_label"], "icon": detail["os_icon"], "color": detail["os_color"]}
                os_source = "headscale"
            else:
                os_info = detect_os(name, given_name)
                os_source = "hostname-guess"

            # Last seen
            ls_obj = n.get("last_seen", {})
            ls_sec = ls_obj.get("seconds", 0) if isinstance(ls_obj, dict) else 0
            last_seen_str = format_ts(ls_obj)
            last_seen_rel = format_relative(ls_sec) if ls_sec else "-"

            # Expiry
            exp_obj = n.get("expiry") or n.get("expiration")
            expiry_str = format_ts(exp_obj)
            is_expired = False
            if isinstance(exp_obj, dict):
                exp_sec = exp_obj.get("seconds", 0)
                if exp_sec and exp_sec < now:
                    is_expired = True

            created_str = format_ts(n.get("created_at"))

            # ACL scope
            if user_name == "martin":
                acl_scope = "전체 허용 (*:*)"
                acl_type = "admin"
                acl_note = "전체 기기 및 모든 포트 접근"
            else:
                acl_scope = "GPU 전용 (:2322, :8889-8895)"
                acl_type = "student"
                acl_note = "관리자:8888 차단 / 타 기기 100% 완전 격리"

            results.append({
                "id": nid,
                "name": name,
                "given_name": given_name,
                "user": user_name,
                "ipv4": ipv4,
                "ipv6": ipv6,
                "online": online,
                "os": os_info["os"],
                "os_icon": os_info["icon"],
                "os_color": os_info["color"],
                "os_source": os_source,
                "os_version": detail.get("os_version"),
                "os_detail": format_os_detail(detail),
                "distro": detail.get("distro"),
                "distro_version": detail.get("distro_version"),
                "distro_codename": detail.get("distro_codename"),
                "arch": detail.get("arch"),
                "device_model": detail.get("device_model"),
                "client_version": detail.get("client_version"),
                "package": detail.get("package"),
                "container": detail.get("container"),
                "desktop": detail.get("desktop"),
                "net_info": detail.get("net"),
                "tpm": detail.get("tpm"),
                "host_info": detail.get("raw"),
                "last_seen": last_seen_str,
                "last_seen_rel": last_seen_rel,
                "expiry": expiry_str,
                "is_expired": is_expired,
                "created_at": created_str,
                "acl_scope": acl_scope,
                "acl_type": acl_type,
                "acl_note": acl_note
            })
        return results
    except Exception as e:
        logger.error(f"Error parsing headscale nodes: {e}")
        return []


def get_acl_policies() -> Dict[str, Any]:
    """Return structured Headscale ACL policies."""
    return {
        "groups": {
            "group:admin": ["martin@"],
            "group:students": ["student1@", "student2@", "student3@"]
        },
        "rules": [
            {
                "group": "👑 관리자 (group:admin)",
                "users": "martin (관리자)",
                "dst": "*:* (망 전체 모든 기기 및 모든 포트 허용)",
                "visibility": "망 전체 모든 등록 단말 가시성 확보 (6대)",
                "isolation": "격리 없음 (전체 메시 통신 가능)",
                "badge": "badge-online"
            },
            {
                "group": "🔒 학생 연구원 (group:students)",
                "users": "student1, student2, student3",
                "dst": "gpu4090:2322 (SSH) • gpu4090:8889-8895 (학생 전용 JupyterLab, 관리자 :8888 차단)",
                "visibility": "오직 본인 기기 + GPU 서버(100.64.0.2) 딱 2대만 노출",
                "isolation": "관리자 포트(:8888) 및 관리자 PC/Mac mini/타 학생 기기 100% 완전 차단/비가시",
                "badge": "badge-local"
            }
        ]
    }


def get_headscale_users() -> List[Dict[str, Any]]:
    """Retrieve all Headscale users/namespaces."""
    raw = run_remote("docker exec headscale headscale users list -o json")
    if not raw:
        return []
    try:
        users = json.loads(raw)
        results = []
        for u in users:
            results.append({
                "id": u.get("id"),
                "name": u.get("name"),
                "created_at": format_ts(u.get("created_at"))
            })
        return results
    except Exception as e:
        logger.error(f"Error parsing headscale users: {e}")
        return []


def get_headscale_preauthkeys() -> List[Dict[str, Any]]:
    """Retrieve all pre-auth keys across users."""
    raw = run_remote("docker exec headscale headscale preauthkeys list -o json")
    if not raw:
        return []
    try:
        keys = json.loads(raw)
        results = []
        now = int(time.time())
        for k in keys:
            u_obj = k.get("user", {})
            user_name = u_obj.get("name") if isinstance(u_obj, dict) else str(u_obj)
            key_str = k.get("key", "")
            reusable = bool(k.get("reusable", False))
            used = bool(k.get("used", False))

            exp_obj = k.get("expiration")
            exp_sec = exp_obj.get("seconds", 0) if isinstance(exp_obj, dict) else 0
            exp_str = format_ts(exp_obj)
            is_expired = exp_sec > 0 and exp_sec < now

            status = "active"
            status_label = "🟢 유효 (Active)"
            if is_expired:
                status = "expired"
                status_label = "⏰ 만료됨 (Expired)"
            elif used and not reusable:
                status = "used"
                status_label = "🔒 사용완료 (Used)"

            results.append({
                "id": k.get("id"),
                "user": user_name,
                "key": key_str,
                "reusable": reusable,
                "used": used,
                "status": status,
                "status_label": status_label,
                "expiration": exp_str,
                "created_at": format_ts(k.get("created_at"))
            })
        results.sort(key=lambda x: x["id"], reverse=True)
        return results
    except Exception as e:
        logger.error(f"Error parsing preauthkeys: {e}")
        return []


def get_vpn_overview() -> Dict[str, Any]:
    """Aggregate Headscale VPN overview statistics and data."""
    nodes = get_headscale_nodes()
    users = get_headscale_users()
    keys = get_headscale_preauthkeys()
    acl = get_acl_policies()

    total_nodes = len(nodes)
    online_nodes = sum(1 for n in nodes if n.get("online"))
    offline_nodes = total_nodes - online_nodes

    active_keys = sum(1 for k in keys if k.get("status") == "active")

    return {
        "server_status": "online",
        "server_version": "v0.29.6",
        "server_endpoint": "http://100.64.0.1:8080",
        "ip_range": "100.64.0.0/10",
        "total_nodes": total_nodes,
        "online_nodes": online_nodes,
        "offline_nodes": offline_nodes,
        "total_users": len(users),
        "active_keys": active_keys,
        "nodes": nodes,
        "users": users,
        "keys": keys,
        "acl": acl
    }


def create_preauth_key(username: str, reusable: bool = False, expiration: str = "720h") -> Dict[str, Any]:
    """Generate a new Headscale pre-auth key for a user."""
    users = get_headscale_users()
    u_match = next((u for u in users if u["name"] == username), None)
    if not u_match:
        # Create user if not existing
        run_remote(f"docker exec headscale headscale users create {shlex.quote(username)}")
        users = get_headscale_users()
        u_match = next((u for u in users if u["name"] == username), None)

    if not u_match:
        return {"success": False, "error": f"사용자 '{username}'를 찾거나 생성할 수 없습니다."}

    uid = u_match["id"]
    reusable_flag = "--reusable" if reusable else ""
    cmd = f"docker exec headscale headscale preauthkeys create --user {uid} --expiration {shlex.quote(expiration)} {reusable_flag} -o json"
    raw = run_remote(cmd)
    if not raw:
        return {"success": False, "error": "Headscale 명령 실행 실패"}

    try:
        res = json.loads(raw)
        key_val = res.get("key", "")
        onboard_cmd = f"tailscale up --login-server http://100.64.0.1:8080 --authkey {key_val}"
        return {
            "success": True,
            "username": username,
            "key": key_val,
            "reusable": reusable,
            "expiration": expiration,
            "onboard_cmd": onboard_cmd
        }
    except Exception as e:
        return {"success": False, "error": f"키 파싱 실패: {e}, raw: {raw}"}


def expire_node(node_id: int) -> Dict[str, Any]:
    """Force expire a node session by ID."""
    cmd = f"docker exec headscale headscale nodes expire -i {int(node_id)}"
    out = run_remote(cmd)
    return {"success": True, "message": f"노드 #{node_id} 세션이 만료 처리되었습니다.", "output": out}


def delete_node(node_id: int) -> Dict[str, Any]:
    """Delete a node from Headscale registry."""
    cmd = f"docker exec headscale headscale nodes delete -i {int(node_id)} --force"
    out = run_remote(cmd)
    return {"success": True, "message": f"노드 #{node_id}가 삭제되었습니다.", "output": out}


def expire_key(key_str: str) -> Dict[str, Any]:
    """Expire a pre-auth key."""
    cmd = f"docker exec headscale headscale preauthkeys expire {shlex.quote(key_str)}"
    out = run_remote(cmd)
    return {"success": True, "message": "사전 인증키가 만료 처리되었습니다.", "output": out}


if __name__ == "__main__":
    overview = get_vpn_overview()
    print(f"Nodes count: {len(overview['nodes'])}")
    print(f"Users count: {len(overview['users'])}")
    print(f"Keys count:  {len(overview['keys'])}")
    for n in overview["nodes"]:
        print(f" - #{n['id']} {n['name']} ({n['user']}) [{n['os']}] IP: {n['ipv4']} Online: {n['online']}")
