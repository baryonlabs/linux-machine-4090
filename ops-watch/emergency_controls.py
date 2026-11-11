#!/usr/bin/env python3
"""Emergency Incident Response Controls for ops-watch.

Provides operational emergency response actions:
1. 사용자별 긴급 차단 (Emergency User Block):
   - Terminate active sessions/processes (pkill -KILL -u <user>)
   - Expire Headscale node & drop from VPN ACL
   - Lock OS account (usermod -L -e 1) and set state: locked
2. 긴급 네트워크 차단 (Emergency Network/VPN Block):
   - Expire Headscale nodes immediately
   - Remove user from Headscale ACL group:students
   - Kill active SSH connection without locking local home/disk
3. 긴급 전체 차단 (Global Panic / Lockdown):
   - Isolate all non-admin users from Headscale VPN network
   - Terminate all student background processes & active SSH sessions
   - Preserves admin (martin) access for forensic triage
4. 긴급 차단 해제 및 정상화 (Restore / Unblock):
   - Re-enable access and restore network routing
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import shutil
import sqlite3
import subprocess
import time
from typing import Any, Dict, List, Optional

ROOT_DIR = pathlib.Path(__file__).parent
DB_PATH = ROOT_DIR / "state" / "ops-watch.db"
BASE_DIR = ROOT_DIR.parent
USERS_YAML_PATH = BASE_DIR / "labops" / "users.yaml"
ACL_FILE_LOCAL = BASE_DIR / "headscale" / "acl.hujson"
REMOTE_ACL_PATH = "/home/martin/headscale/config/acl.hujson"
ADMIN_USER = "martin"


def run_ssh_or_local(cmd: List[str], timeout: int = 15) -> subprocess.CompletedProcess[str]:
    """Execute command via SSH to linux-builder or fallback to local."""
    ssh_cmd = ["ssh", "-o", "ConnectTimeout=4", "linux-builder"] + cmd
    try:
        r = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=timeout)
        if r.returncode == 0:
            return r
    except Exception:
        pass
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def log_emergency_event(kind: str, body: str, tags: str = "emergency-control") -> None:
    """Record emergency action into durable worklog in ops-watch.db."""
    if DB_PATH.exists():
        try:
            conn = sqlite3.connect(DB_PATH)
            now = int(time.time())
            conn.execute(
                "INSERT INTO worklog(created, ticket_id, kind, body, tags) VALUES(?,?,?,?,?)",
                (now, None, kind, body, tags)
            )
            conn.commit()
            conn.close()
        except Exception:
            pass


def get_headscale_students() -> List[str]:
    """Read students currently in Headscale ACL group:students."""
    if ACL_FILE_LOCAL.exists():
        try:
            text = ACL_FILE_LOCAL.read_text(encoding="utf-8")
            m = re.search(r'"group:students"\s*:\s*\[(.*?)\]', text, re.S)
            if m:
                return re.findall(r'"([^\"]+)@"', m.group(1))
        except Exception:
            pass
    return []


def update_headscale_students(students: List[str]) -> bool:
    """Update group:students in both local and remote Headscale ACL and reload."""
    clean_students = sorted(set(students))
    formatted = ", ".join(f'"{s}@"' for s in clean_students)
    
    if not ACL_FILE_LOCAL.exists():
        return False

    text = ACL_FILE_LOCAL.read_text(encoding="utf-8")
    new_text = re.sub(
        r'("group:students"\s*:\s*\[)(.*?)(\])',
        r'\g<1>' + (f" {formatted} " if formatted else "") + r'\g<3>',
        text,
        flags=re.S
    )
    ACL_FILE_LOCAL.write_text(new_text, encoding="utf-8")

    # Sync to remote host
    try:
        scp = subprocess.run(
            ["scp", "-o", "ConnectTimeout=4", str(ACL_FILE_LOCAL), f"linux-builder:{REMOTE_ACL_PATH}"],
            capture_output=True, text=True, timeout=10
        )
        if scp.returncode == 0:
            run_ssh_or_local(["docker", "exec", "headscale", "headscale", "policy", "check", "-f", "/etc/headscale/acl.hujson"])
            run_ssh_or_local(["docker", "restart", "headscale"])
            return True
    except Exception:
        pass
    return False


def expire_user_headscale_nodes(username: str) -> List[int]:
    """Find and expire all Headscale nodes belonging to the given user."""
    expired_ids = []
    try:
        r = run_ssh_or_local(["docker", "exec", "headscale", "headscale", "nodes", "list", "-o", "json"])
        if r.returncode == 0 and r.stdout.strip():
            nodes = json.loads(r.stdout.strip())
            for n in nodes:
                u_name = n.get("user", {}).get("name") if isinstance(n.get("user"), dict) else n.get("user")
                if u_name == username and not n.get("expired"):
                    nid = n.get("id")
                    if nid:
                        run_ssh_or_local(["docker", "exec", "headscale", "headscale", "nodes", "expire", "-i", str(nid)])
                        expired_ids.append(nid)
    except Exception:
        pass
    return expired_ids


def set_user_yaml_state(username: str, state: str) -> bool:
    """Set user state in labops/users.yaml (e.g. active or locked)."""
    if not USERS_YAML_PATH.exists():
        return False
    try:
        content = USERS_YAML_PATH.read_text(encoding="utf-8")
        pattern = rf"(- name: {username}\b.*?state: )\w+"
        new_content = re.sub(pattern, rf"\g<1>{state}", content, flags=re.S)
        if new_content != content:
            USERS_YAML_PATH.write_text(new_content, encoding="utf-8")
            return True
    except Exception:
        pass
    return False


def emergency_block_user(username: str, reason: str = "보안 위협 감지로 인한 긴급 격리 차단") -> Dict[str, Any]:
    """Full user lockout: kill sessions/processes, lock OS account, expire VPN nodes, drop from ACL."""
    if username == ADMIN_USER:
        return {"success": False, "error": f"관리자 계정 '{ADMIN_USER}'은(는) 긴급 차단할 수 없습니다."}

    actions_taken = []

    # 1. Terminate all active processes & SSH sessions
    kill_cmd = f"pkill -KILL -u {username} 2>/dev/null || true"
    run_ssh_or_local(["bash", "-c", kill_cmd])
    actions_taken.append(f"프로세스 및 활성 세션 강제 종료 (pkill -KILL -u {username})")

    # 2. Expire Headscale VPN nodes
    expired_nodes = expire_user_headscale_nodes(username)
    if expired_nodes:
        actions_taken.append(f"Headscale VPN 접속 노드 즉시 만료 (Node ID: {expired_nodes})")

    # 3. Remove user from Headscale ACL
    current_students = get_headscale_students()
    if username in current_students:
        updated = [s for s in current_students if s != username]
        if update_headscale_students(updated):
            actions_taken.append("Headscale ACL group:students에서 제거 (WireGuard 패킷 즉시 차단)")

    # 4. Lock account in users.yaml and OS
    set_user_yaml_state(username, "locked")
    run_ssh_or_local(["sudo", "usermod", "-L", "-e", "1", username])
    actions_taken.append(f"OS 계정 잠금 및 만료 처리 (usermod -L -e 1 {username})")

    msg = f"[긴급 차단] 사용자 '{username}' 계정 및 네트워크 전면 차단 완료.\n사유: {reason}\n조치 내역:\n- " + "\n- ".join(actions_taken)
    log_emergency_event("emergency-user-block", msg, tags=f"emergency,lockout,{username}")

    return {
        "success": True,
        "username": username,
        "actions_taken": actions_taken,
        "message": f"사용자 '{username}'의 계정 및 네트워크가 성공적으로 긴급 차단되었습니다."
    }


def emergency_network_block(username: str, reason: str = "의심 단말 접속으로 인한 VPN 네트워크 격리") -> Dict[str, Any]:
    """Network-only isolation: expire VPN nodes and drop from ACL without locking local OS files."""
    if username == ADMIN_USER:
        return {"success": False, "error": f"관리자 계정 '{ADMIN_USER}'은(는) 네트워크 차단할 수 없습니다."}

    actions_taken = []

    # 1. Expire Headscale VPN nodes
    expired_nodes = expire_user_headscale_nodes(username)
    if expired_nodes:
        actions_taken.append(f"Headscale VPN 접속 노드 즉시 만료 (Node ID: {expired_nodes})")

    # 2. Remove user from Headscale ACL
    current_students = get_headscale_students()
    if username in current_students:
        updated = [s for s in current_students if s != username]
        if update_headscale_students(updated):
            actions_taken.append("Headscale ACL group:students에서 제거")

    # 3. Kill active SSH connection
    run_ssh_or_local(["bash", "-c", f"pkill -f 'sshd: {username}' 2>/dev/null || true"])
    actions_taken.append(f"사용자 '{username}'의 활성 SSH 터널링 세션 즉시 단절")

    msg = f"[긴급 네트워크 차단] 사용자 '{username}'의 VPN 접근 격리 완료.\n사유: {reason}\n조치 내역:\n- " + "\n- ".join(actions_taken)
    log_emergency_event("emergency-network-block", msg, tags=f"emergency,network-isolation,{username}")

    return {
        "success": True,
        "username": username,
        "actions_taken": actions_taken,
        "message": f"사용자 '{username}'의 VPN 네트워크 접근이 격리 차단되었습니다. (로컬 계정 유지)"
    }


def emergency_global_lockdown(reason: str = "침해사고 의심에 따른 전사 비상 격리(Panic Lockdown)") -> Dict[str, Any]:
    """Emergency Panic Button: Isolate ALL students from network and kill student sessions immediately."""
    actions_taken = []

    # 1. Isolate Headscale ACL: empty group:students
    if update_headscale_students([]):
        actions_taken.append("Headscale ACL 내 전체 학생 그룹(group:students) 완전 격리 (WireGuard 패킷 전면 드롭)")

    # 2. Expire all non-admin Headscale nodes
    try:
        r = run_ssh_or_local(["docker", "exec", "headscale", "headscale", "nodes", "list", "-o", "json"])
        if r.returncode == 0 and r.stdout.strip():
            nodes = json.loads(r.stdout.strip())
            for n in nodes:
                u_name = n.get("user", {}).get("name") if isinstance(n.get("user"), dict) else n.get("user")
                if u_name != ADMIN_USER and not n.get("expired"):
                    nid = n.get("id")
                    if nid:
                        run_ssh_or_local(["docker", "exec", "headscale", "headscale", "nodes", "expire", "-i", str(nid)])
            actions_taken.append("전체 학생 단말 Headscale Node 만료 처리")
    except Exception:
        pass

    # 3. Kill all student sessions
    student_users = ["student1", "student2", "student3", "student5", "student6", "student4"]
    for su in student_users:
        run_ssh_or_local(["bash", "-c", f"pkill -KILL -u {su} 2>/dev/null || true"])
    actions_taken.append(f"모든 학생 계정({len(student_users)}명)의 백그라운드 프로세스 및 SSH 세션 전면 강제 종료")
    actions_taken.append(f"관리자('{ADMIN_USER}') 비상 접속 세션 및 포렌식 채널 정상 유지")

    # Record state in db
    if DB_PATH.exists():
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.execute("CREATE TABLE IF NOT EXISTS system_lockdown (is_locked INTEGER, reason TEXT, updated INTEGER)")
            conn.execute("DELETE FROM system_lockdown")
            conn.execute("INSERT INTO system_lockdown VALUES(1, ?, ?)", (reason, int(time.time())))
            conn.commit()
            conn.close()
        except Exception:
            pass

    msg = f"🚨 [긴급 전체 차단 발령] 관리자 비상 락다운(Global Lockdown) 실행 완료.\n사유: {reason}\n조치:\n- " + "\n- ".join(actions_taken)
    log_emergency_event("emergency-global-lockdown", msg, tags="panic-lockdown,critical,all-users")

    return {
        "success": True,
        "is_locked": True,
        "actions_taken": actions_taken,
        "message": "서버 전체 학생 접근이 긴급 차단(Lockdown)되었습니다. 관리자 세션만 유지됩니다."
    }


def restore_global_lockdown() -> Dict[str, Any]:
    """Restore normal operations after global lockdown."""
    # Restore students to Headscale ACL
    active_students = ["student1", "student2", "student3"]
    update_headscale_students(active_students)

    # Clear lockdown state in db
    if DB_PATH.exists():
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.execute("CREATE TABLE IF NOT EXISTS system_lockdown (is_locked INTEGER, reason TEXT, updated INTEGER)")
            conn.execute("DELETE FROM system_lockdown")
            conn.execute("INSERT INTO system_lockdown VALUES(0, '정상 복구', ?)", (int(time.time()),))
            conn.commit()
            conn.close()
        except Exception:
            pass

    msg = "🟢 [비상 락다운 해제] 서버 정상 복구 완료. 활성 학생 계정(student1, student2, student3)의 VPN 통신이 재개되었습니다."
    log_emergency_event("emergency-global-restore", msg, tags="lockdown-restore,normal")

    return {
        "success": True,
        "is_locked": False,
        "message": "긴급 차단이 정상 해제되었습니다. 학생 연구원 VPN 통신이 재개되었습니다."
    }


def is_global_locked() -> bool:
    """Check if system is currently under emergency global lockdown."""
    if DB_PATH.exists():
        try:
            conn = sqlite3.connect(DB_PATH)
            row = conn.execute("SELECT is_locked FROM system_lockdown LIMIT 1").fetchone()
            conn.close()
            if row:
                return bool(row[0])
        except Exception:
            pass
    return False


def unblock_user(username: str) -> Dict[str, Any]:
    """Unblock locked user: set active in users.yaml, unlock OS account, restore Headscale ACL."""
    if username == ADMIN_USER:
        return {"success": False, "error": "관리자 계정입니다."}

    # Unlock in users.yaml and OS
    set_user_yaml_state(username, "active")
    run_ssh_or_local(["sudo", "usermod", "-U", "-e", "2027-01-04", username])

    # Restore in Headscale ACL
    students = get_headscale_students()
    if username not in students:
        students.append(username)
        update_headscale_students(students)

    msg = f"🟢 [차단 해제] 사용자 '{username}' 계정 및 VPN 정상 복구 완료."
    log_emergency_event("emergency-user-unblock", msg, tags=f"unblock,{username}")

    return {
        "success": True,
        "username": username,
        "message": f"사용자 '{username}'의 차단이 해제되어 정상 활성화되었습니다."
    }


if __name__ == "__main__":
    print(f"Current Headscale Students: {get_headscale_students()}")
    print(f"Global Lockdown Active: {is_global_locked()}")
