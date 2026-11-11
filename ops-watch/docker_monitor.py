#!/usr/bin/env python3
"""Docker Container & Multi-Tenant JupyterLab Monitor for ops-watch v2.

Inspects, maps GPU workloads, and provides container lifecycle control:
1. Lists all running and stopped containers on host.
2. Identifies multi-tenant JupyterLab containers (e.g. *_jupyter).
3. Provides container start/stop/restart operations.
4. Maps active GPU compute PIDs to specific Docker container names.
"""

from __future__ import annotations

import json
import subprocess
from typing import Any, Dict, List, Optional


def run_remote(cmd: str) -> str:
    """Run command on linux-builder host via SSH."""
    try:
        r = subprocess.run(
            ["ssh", "-o", "ConnectTimeout=4", "linux-builder", cmd],
            capture_output=True, text=True, timeout=8
        )
        if r.returncode == 0:
            return r.stdout
    except Exception:
        pass
    return ""


def get_containers_list() -> List[Dict[str, Any]]:
    """Retrieve list of Docker containers with status, ports, and tenant identification."""
    raw = run_remote("docker ps -a --format '{{json .}}'")
    if not raw.strip():
        return []

    containers = []
    for line in raw.strip().splitlines():
        if not line.strip():
            continue
        try:
            d = json.loads(line)
            name = d.get("Names", "")
            image = d.get("Image", "")
            state = d.get("State", "")
            status = d.get("Status", "")
            ports = d.get("Ports", "")
            cid = d.get("ID", "")

            is_jupyter = "jupyter" in name.lower() or "pytorch" in image.lower()
            tenant = name.split("_")[0] if "_" in name else ("admin" if "martin" in name else "shared")

            containers.append({
                "id": cid,
                "name": name,
                "image": image,
                "state": state, # running, exited, paused
                "status": status,
                "ports": ports,
                "is_jupyter": is_jupyter,
                "tenant": tenant
            })
        except Exception:
            continue

    return containers


def control_container(name: str, action: str) -> Dict[str, Any]:
    """Execute lifecycle action (start, stop, restart, up) on a target container."""
    if action not in ("start", "stop", "restart", "up"):
        return {"success": False, "error": f"Invalid action '{action}'. Use start, stop, restart, or up."}

    # Strict name validation to prevent command injection
    import re
    if not re.match(r"^[a-zA-Z0-9_\-]+$", name):
        return {"success": False, "error": "Invalid container name"}

    res = run_remote(f"docker {action} {name}")
    if res.strip() == name:
        return {"success": True, "message": f"컨테이너 '{name}' {action} 명령 완료"}

    # If action is start/up and container was not yet initialized from docker-compose
    if action in ("start", "up"):
        svc_name = name.replace("_", "-")
        run_remote(f"cd ~/jupyter-infra && docker compose up -d {svc_name} 2>&1")
        cur = get_containers_list()
        matching = [c for c in cur if c["name"] in (name, svc_name)]
        if matching:
            return {"success": True, "message": f"컨테이너 '{name}' docker compose 기동 완료 (상태: {matching[0]['state']})"}

    # Check if state changed anyway
    cur = get_containers_list()
    matching = [c for c in cur if c["name"] == name]
    if matching:
        return {"success": True, "message": f"컨테이너 '{name}' {action} 처리됨 (상태: {matching[0]['state']})"}
    return {"success": False, "error": f"컨테이너 '{name}' {action} 실패"}


def write_remote_file(remote_path: str, content: str) -> bool:
    """Write string content to remote file via SSH pipe."""
    try:
        p = subprocess.Popen(
            ["ssh", "-o", "ConnectTimeout=4", "linux-builder", f"cat > {remote_path}"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        p.communicate(input=content, timeout=10)
        return p.returncode == 0
    except Exception:
        return False


def get_allocated_jupyter_services() -> Dict[str, Dict[str, Any]]:
    """Parse remote docker-compose.yml to list existing JupyterLab services and their ports/tokens."""
    import re
    compose_content = run_remote("cat ~/jupyter-infra/docker-compose.yml")
    if not compose_content:
        return {}

    services: Dict[str, Dict[str, Any]] = {}
    current_svc = None
    for line in compose_content.splitlines():
        svc_match = re.match(r"^\s\s([a-zA-Z0-9_\-]+-jupyter):", line)
        if svc_match:
            current_svc = svc_match.group(1).replace("-jupyter", "")
            services[current_svc] = {"name": current_svc, "port": None, "token": None}
            continue

        if current_svc:
            port_match = re.search(r"127\.0\.0\.1:(\d+):", line) or re.search(r"--port=(\d+)", line)
            if port_match and not services[current_svc].get("port"):
                services[current_svc]["port"] = int(port_match.group(1))

            token_match = re.search(r"--(?:ServerApp|NotebookApp|IdentityProvider)\.token=['\"]([^'\"]+)['\"]", line)
            if token_match:
                services[current_svc]["token"] = token_match.group(1)

    return services


def provision_jupyter_container(username: str, token: Optional[str] = None) -> Dict[str, Any]:
    """Dynamically allocate unique port, token, and docker-compose.yml entry for a researcher."""
    import re
    import secrets

    username = username.strip().lower()
    if not re.match(r"^[a-zA-Z0-9_\-]+$", username):
        return {"success": False, "error": "유효하지 않은 사용자 ID 형식입니다."}

    compose_content = run_remote("cat ~/jupyter-infra/docker-compose.yml")
    if not compose_content:
        return {"success": False, "error": "docker-compose.yml을 불러올 수 없습니다."}

    # Extract all allocated ports
    allocated_ports = [int(p) for p in re.findall(r"127\.0\.0\.1:(\d+):", compose_content)]
    if not allocated_ports:
        allocated_ports = [8888]

    # Check if already provisioned
    existing_services = get_allocated_jupyter_services()
    if username in existing_services:
        svc_info = existing_services[username]
        assigned_port = svc_info.get("port") or 8888
        assigned_token = svc_info.get("token") or "existing-token"
        return {
            "success": True,
            "username": username,
            "container_name": f"{username}_jupyter",
            "port": assigned_port,
            "token": assigned_token,
            "jupyter_url": f"http://100.64.0.2:{assigned_port}/?token={assigned_token}",
            "already_existed": True
        }

    next_port = max(allocated_ports) + 1
    new_token = token or secrets.token_hex(8)

    service_block = f"""
  # Student Researcher ({username})
  {username}-jupyter:
    image: nvcr.io/nvidia/pytorch:24.04-py3
    container_name: {username}_jupyter
    restart: unless-stopped
    ipc: host
    shm_size: 16gb
    ports:
      - {next_port}:{next_port}
    volumes:
      - /mnt/data/users/{username}/jupyter_home:/workspace
      - /mnt/data/users/{username}:/workspace/data_root
      - /home/{username}:/workspace/home
    working_dir: /workspace
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: all
              capabilities: [gpu]
    command: >
      jupyter lab --ip=0.0.0.0 --port={next_port} --no-browser --allow-root
      --NotebookApp.token='{new_token}'
      --NotebookApp.allow_origin='*'
      --NotebookApp.password=''
"""
    new_compose = compose_content.rstrip() + service_block
    ok = write_remote_file("~/jupyter-infra/docker-compose.yml", new_compose)
    if not ok:
        return {"success": False, "error": "원격 docker-compose.yml 파일 쓰기에 실패했습니다."}

    # Prepare storage directory
    run_remote(f"mkdir -p /mnt/data/users/{username}/jupyter_home")

    return {
        "success": True,
        "username": username,
        "container_name": f"{username}_jupyter",
        "port": next_port,
        "token": new_token,
        "jupyter_url": f"http://100.64.0.2:{next_port}/?token={new_token}",
        "already_existed": False
    }


if __name__ == "__main__":
    conts = get_containers_list()
    print(f"Total Containers: {len(conts)}")
    for c in conts:
        print(f" - {c['name']:20} {c['state']:10} {c['ports']}")
