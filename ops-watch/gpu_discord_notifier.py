#!/usr/bin/env python3
"""RTX 4090 GPU Usage Change Monitor & Discord Notifier for Lab Researchers.

Features:
1. Inspects NVIDIA GeForce RTX 4090 (24GB VRAM) utilization & memory usage every 10 minutes.
2. If GPU utilization or VRAM percentage changes by >= 10% compared to last notified state,
   sends a friendly, informative embed message to the lab Discord channel.
3. Designed specifically for student researchers to check GPU availability, current users,
   and remind them of GPU memory hygiene (Shut Down All Kernels).
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import pathlib
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

BASE_DIR = pathlib.Path(__file__).parent
STATE_FILE = BASE_DIR / "state" / "gpu_monitor_state.json"
WEBHOOK_URL_PATHS = [
    BASE_DIR.parent / "secrets" / "discord-webhook.url",
    pathlib.Path("/etc/labops/discord-webhook.url"),
    pathlib.Path.home() / ".labops-discord-webhook.url",
    pathlib.Path.home() / "labops" / "discord-webhook.url",
]

VRAM_TOTAL_MB = 24564.0  # RTX 4090 24GB


def get_webhook_url() -> Optional[str]:
    """Retrieve Discord webhook URL from environment or known secure files."""
    env_url = os.environ.get("DISCORD_WEBHOOK_URL")
    if env_url and env_url.startswith("https://discord.com/api/webhooks/"):
        return env_url.strip()

    for p in WEBHOOK_URL_PATHS:
        try:
            if p.exists():
                content = p.read_text(encoding="utf-8").strip()
                if content.startswith("https://discord.com/api/webhooks/"):
                    return content
        except Exception:
            continue
    return None


def query_gpu_metrics() -> Dict[str, Any]:
    """Query live GPU utilization, VRAM, thermals, and active compute processes."""
    cmd = "nvidia-smi --query-gpu=utilization.gpu,memory.used,memory.total,temperature.gpu,power.draw,driver_version --format=csv,noheader,nounits"
    out = ""

    # 1. Local execution
    if shutil.which("nvidia-smi"):
        try:
            r = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=5)
            if r.returncode == 0 and r.stdout.strip():
                out = r.stdout.strip()
        except Exception:
            pass

    # 2. Remote execution via SSH if local is not GPU host
    if not out:
        try:
            r = subprocess.run(
                ["ssh", "-o", "ConnectTimeout=4", "linux-builder", cmd],
                capture_output=True, text=True, timeout=6
            )
            if r.returncode == 0 and r.stdout.strip():
                out = r.stdout.strip()
        except Exception:
            pass

    if not out:
        raise RuntimeError("Failed to query nvidia-smi both locally and remotely.")

    parts = [x.strip() for x in out.split(",")]
    util_pct = int(parts[0]) if len(parts) > 0 else 0
    mem_used_mb = int(parts[1]) if len(parts) > 1 else 0
    mem_total_mb = int(parts[2]) if len(parts) > 2 else int(VRAM_TOTAL_MB)
    temp_c = int(parts[3]) if len(parts) > 3 else 0
    pwr_w = float(parts[4]) if len(parts) > 4 else 0.0
    driver = parts[5] if len(parts) > 5 else "N/A"

    vram_pct = round((mem_used_mb / mem_total_mb) * 100.0, 1)
    vram_used_gb = round(mem_used_mb / 1024.0, 2)
    vram_total_gb = round(mem_total_mb / 1024.0, 1)
    vram_free_gb = round((mem_total_mb - mem_used_mb) / 1024.0, 2)

    # Query compute apps
    procs = []
    p_cmd = "nvidia-smi --query-compute-apps=pid,process_name,used_gpu_memory --format=csv,noheader,nounits"
    p_out = ""

    if shutil.which("nvidia-smi"):
        try:
            pr = subprocess.run(p_cmd.split(), capture_output=True, text=True, timeout=5)
            if pr.returncode == 0 and pr.stdout.strip():
                p_out = pr.stdout.strip()
        except Exception:
            pass

    if not p_out:
        try:
            pr = subprocess.run(
                ["ssh", "-o", "ConnectTimeout=4", "linux-builder", p_cmd],
                capture_output=True, text=True, timeout=6
            )
            if pr.returncode == 0 and pr.stdout.strip():
                p_out = pr.stdout.strip()
        except Exception:
            pass

    if p_out:
        for line in p_out.splitlines():
            line = line.strip()
            if not line:
                continue
            p_parts = [x.strip() for x in line.split(",")]
            if len(p_parts) >= 3:
                pid = p_parts[0]
                pname = p_parts[1]
                used_mib = p_parts[2]

                # Lookup username for PID
                u_cmd = f"ps -p {pid} -o user=,args="
                u_user = "unknown"
                u_args = pname
                try:
                    if shutil.which("ps") and sys.platform.startswith("linux"):
                        ur = subprocess.run(u_cmd, shell=True, capture_output=True, text=True, timeout=3)
                    else:
                        ur = subprocess.run(["ssh", "-o", "ConnectTimeout=3", "linux-builder", u_cmd], capture_output=True, text=True, timeout=4)
                    if ur.returncode == 0 and ur.stdout.strip():
                        u_split = ur.stdout.strip().split(None, 1)
                        if u_split:
                            u_user = u_split[0]
                        if len(u_split) > 1:
                            u_args = u_split[1]
                except Exception:
                    pass

                procs.append({
                    "pid": pid,
                    "user": u_user,
                    "name": pname,
                    "args": u_args[:100],
                    "used_gb": round(int(used_mib) / 1024.0, 2)
                })

    return {
        "device": "NVIDIA GeForce RTX 4090",
        "driver": driver,
        "util_pct": util_pct,
        "vram_pct": vram_pct,
        "vram_used_gb": vram_used_gb,
        "vram_total_gb": vram_total_gb,
        "vram_free_gb": vram_free_gb,
        "temp_c": temp_c,
        "power_w": pwr_w,
        "processes": procs,
        "timestamp": datetime.datetime.now().isoformat()
    }


def load_previous_state() -> Dict[str, Any]:
    """Load previously saved monitor state."""
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {
        "last_notified_util_pct": 0,
        "last_notified_vram_pct": 0.0,
        "last_checked_at": None,
        "last_notified_at": None
    }


def save_current_state(state: Dict[str, Any]) -> None:
    """Save current state to json file."""
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")


def build_discord_embed(
    metrics: Dict[str, Any],
    diff_util: int,
    diff_vram: float,
    prev_util: int,
    prev_vram: float,
    is_initial: bool = False
) -> Dict[str, Any]:
    """Build a rich, beautiful Discord embed tailored for lab students."""
    util = metrics["util_pct"]
    vram_used = metrics["vram_used_gb"]
    vram_total = metrics["vram_total_gb"]
    vram_pct = metrics["vram_pct"]
    vram_free = metrics["vram_free_gb"]
    temp = metrics["temp_c"]
    pwr = metrics["power_w"]
    procs = metrics["processes"]

    # 1. Status classification & Embed color
    if util >= 70 or vram_pct >= 75:
        status_badge = "🔴 [고부하] 대규모 딥러닝 연산/훈련 진행 중"
        color = 0xE74C3C  # Red
        status_desc = "현재 GPU 연산 또는 VRAM 점유율이 높습니다. 추가 대규모 학습 실행 전 자원 현황을 확인해 주세요."
    elif util >= 15 or vram_pct >= 25:
        status_badge = "🟡 [사용 중] 연구원 실험 및 모델 로드 중"
        color = 0xF39C12  # Orange
        status_desc = "현재 일부 GPU 자원이 사용 중입니다. 가용 VRAM 용량 내에서 실험 진행이 가능합니다."
    else:
        status_badge = "🟢 [여유] 전체 자원 가용 (모든 학생 사용 가능)"
        color = 0x2ECC71  # Green
        status_desc = "현재 GPU 및 VRAM 자원이 여유롭습니다. 언제든지 JupyterLab에서 실험을 시작하실 수 있습니다."

    # 2. Change summary
    if is_initial:
        change_summary = "📢 **모니터링 알림 시작**: 현재 연구실 GPU 실시간 상태 기준점 설정"
    else:
        changes = []
        if abs(diff_util) >= 10:
            arrow = "▲" if diff_util > 0 else "▼"
            changes.append(f"GPU 연산률: `{prev_util}%` ➔ **`{util}%`** ({arrow} {abs(diff_util)}%p)")
        if abs(diff_vram) >= 10.0:
            arrow = "▲" if diff_vram > 0 else "▼"
            changes.append(f"VRAM 점유율: `{prev_vram:.1f}%` ➔ **`{vram_pct:.1f}%`** ({arrow} {abs(diff_vram):.1f}%p)")
        change_summary = "⚡ **자원 변동 감지 (10% 이상 변화)**:\n• " + "\n• ".join(changes)

    # 3. Process breakdown
    if procs:
        proc_lines = []
        for p in procs[:5]:
            proc_lines.append(f"• **`{p['user']}`** (PID {p['pid']}): `{p['used_gb']} GB VRAM` ({p['name']})")
        if len(procs) > 5:
            proc_lines.append(f"• ... 외 {len(procs) - 5}개 프로세스")
        proc_text = "\n".join(proc_lines)
    else:
        proc_text = "✨ *현재 GPU를 점유 중인 프로세스 없음 (완전 유휴 상태)*"

    fields = [
        {
            "name": "📊 GPU 연산 점유율",
            "value": f"**`{util}%`** (직전: {prev_util}%)",
            "inline": True
        },
        {
            "name": "🧠 VRAM 사용 현황",
            "value": f"**`{vram_used} GB`** / {vram_total} GB (`{vram_pct}%`)\n👉 **가용 여유: `{vram_free} GB`**",
            "inline": True
        },
        {
            "name": "🌡️ 하드웨어 상태",
            "value": f"온도: `{temp}°C` | 전력: `{pwr:.1f}W` / 450W",
            "inline": True
        },
        {
            "name": "👤 실행 중인 프로세스 및 사용자",
            "value": proc_text,
            "inline": False
        },
        {
            "name": "📌 연구실 이용 에티켓 & 접속 바로가기",
            "value": (
                "1. **VRAM 반납 필수**: 브라우저 탭만 닫으면 VRAM이 해제되지 않습니다. 실험 종료 시 반드시 JupyterLab 상단 **`Kernel` ➔ `Shut Down All Kernels`**를 클릭해 주세요!\n"
                "2. **개인별 JupyterLab**: [Student One(:8889)](http://100.64.0.2:8889) | [Student Two(:8890)](http://100.64.0.2:8890) | [Student Three(:8891)](http://100.64.0.2:8891) *(VPN 필요)*"
            ),
            "inline": False
        }
    ]

    embed = {
        "title": f"⚡ [martin-B650M-K] RTX 4090 GPU 상태 안내: {status_badge}",
        "description": f"{change_summary}\n\n> {status_desc}",
        "color": color,
        "fields": fields,
        "footer": {
            "text": "martin-B650M-K LabOps • 10분 주기 GPU 변동 감지 알림"
        },
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }

    return embed


def send_discord_webhook(webhook_url: str, embed: Dict[str, Any]) -> bool:
    """Send payload to Discord webhook."""
    payload = {
        "username": "LabOps RTX 4090 Bot",
        "avatar_url": "https://raw.githubusercontent.com/nvidia/logos/main/nvidia-logo-vert.png",
        "embeds": [embed]
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "LabOps-GPU-Monitor/2.0"
        }
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status in (200, 204)
    except urllib.error.HTTPError as e:
        print(f"Discord webhook HTTP Error {e.code}: {e.read().decode('utf-8')}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"Failed to post to Discord webhook: {e}", file=sys.stderr)
        return False


def check_and_notify(threshold: float = 10.0, force: bool = False) -> Dict[str, Any]:
    """Execute a single check cycle and send webhook if delta >= threshold."""
    webhook_url = get_webhook_url()
    if not webhook_url:
        raise ValueError("Discord Webhook URL not found in config or environment.")

    metrics = query_gpu_metrics()
    prev_state = load_previous_state()

    prev_notified_util = prev_state.get("last_notified_util_pct")
    prev_notified_vram = prev_state.get("last_notified_vram_pct")

    is_initial = (prev_notified_util is None or prev_notified_vram is None)
    if is_initial:
        prev_notified_util = 0
        prev_notified_vram = 0.0

    diff_util = metrics["util_pct"] - prev_notified_util
    diff_vram = metrics["vram_pct"] - prev_notified_vram

    should_notify = force or (abs(diff_util) >= threshold) or (abs(diff_vram) >= threshold)

    result = {
        "checked_at": metrics["timestamp"],
        "current_util_pct": metrics["util_pct"],
        "current_vram_pct": metrics["vram_pct"],
        "prev_notified_util_pct": prev_notified_util,
        "prev_notified_vram_pct": prev_notified_vram,
        "diff_util_pct": diff_util,
        "diff_vram_pct": diff_vram,
        "should_notify": should_notify,
        "notified": False,
        "force": force
    }

    if should_notify:
        embed = build_discord_embed(
            metrics=metrics,
            diff_util=diff_util,
            diff_vram=diff_vram,
            prev_util=prev_notified_util,
            prev_vram=prev_notified_vram,
            is_initial=is_initial and not force
        )
        ok = send_discord_webhook(webhook_url, embed)
        result["notified"] = ok
        if ok:
            prev_state["last_notified_util_pct"] = metrics["util_pct"]
            prev_state["last_notified_vram_pct"] = metrics["vram_pct"]
            prev_state["last_notified_at"] = metrics["timestamp"]

    prev_state["last_checked_at"] = metrics["timestamp"]
    prev_state["last_util_pct"] = metrics["util_pct"]
    prev_state["last_vram_pct"] = metrics["vram_pct"]
    save_current_state(prev_state)

    return result


def main():
    parser = argparse.ArgumentParser(description="Monitor RTX 4090 GPU and alert Discord on 10% change.")
    parser.add_argument("--threshold", type=float, default=10.0, help="Change threshold percentage (default: 10.0)")
    parser.add_argument("--force", action="store_true", help="Force send Discord notification regardless of delta")
    parser.add_argument("--daemon", action="store_true", help="Run continuously in a loop every 10 minutes")
    parser.add_argument("--interval", type=int, default=600, help="Loop interval in seconds (default: 600s / 10min)")
    args = parser.parse_args()

    if args.daemon:
        print(f"Starting GPU change monitoring daemon (interval: {args.interval}s, threshold: {args.threshold}%)...")
        while True:
            try:
                res = check_and_notify(threshold=args.threshold, force=False)
                ts = res["checked_at"]
                if res["notified"]:
                    print(f"[{ts}] Sent Discord notification! Delta: util={res['diff_util_pct']}%, vram={res['diff_vram_pct']:.1f}%")
                else:
                    print(f"[{ts}] Checked. No significant change (util: {res['current_util_pct']}%, vram: {res['current_vram_pct']}%)")
            except Exception as e:
                print(f"Error in monitor loop: {e}", file=sys.stderr)
            time.sleep(args.interval)
    else:
        res = check_and_notify(threshold=args.threshold, force=args.force)
        print(json.dumps(res, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
