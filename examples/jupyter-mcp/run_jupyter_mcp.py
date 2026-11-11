#!/usr/bin/env python3
"""Launcher for datalayer/jupyter-mcp-server with universal Jupyter auth compatibility.

Ensures compatibility with both modern JupyterLab 4.x and classic JupyterLab/Notebook
by transmitting the standard 'Authorization: token <token>' header required by Tornado.
"""

from __future__ import annotations

import os
import sys

# Default remote RTX 4090 admin JupyterLab credentials
DEFAULT_URL = "http://100.64.0.2:8888"
DEFAULT_TOKEN = "REDACTED-JUPYTER-TOKEN"

server_url = os.environ.get("CODE_SANDBOX_URL") or os.environ.get("SERVER_URL") or DEFAULT_URL
token = os.environ.get("CODE_SANDBOX_TOKEN") or os.environ.get("TOKEN") or DEFAULT_TOKEN

os.environ["CODE_SANDBOX_URL"] = server_url
os.environ["CODE_SANDBOX_TOKEN"] = token
os.environ["SERVER_URL"] = server_url
os.environ["TOKEN"] = token

# 1. Patch jupyter_server_client for REST & contents endpoints
try:
    import jupyter_server_client.http_client as jsc_http

    _orig_jsc_init = jsc_http.BaseHTTPClient.__init__

    def _patched_jsc_init(self, *args, **kwargs):
        _orig_jsc_init(self, *args, **kwargs)
        cur_token = self.token or token
        if cur_token:
            self.session.headers["Authorization"] = f"token {cur_token}"

    jsc_http.BaseHTTPClient.__init__ = _patched_jsc_init
except Exception as e:
    sys.stderr.write(f"[WARN] Failed to patch jupyter_server_client: {e}\n")

# 2. Patch jupyter_kernel_client for kernel lifecycle endpoints
try:
    import jupyter_kernel_client.manager as jkm

    _orig_jkm_fetch = jkm.fetch

    def _patched_jkm_fetch(request, *args, **kwargs):
        cur_token = kwargs.get("token") or token
        headers = kwargs.setdefault("headers", {})
        headers["Authorization"] = f"token {cur_token}"
        return _orig_jkm_fetch(request, *args, **kwargs)

    jkm.fetch = _patched_jkm_fetch
except Exception as e:
    sys.stderr.write(f"[WARN] Failed to patch jupyter_kernel_client: {e}\n")

if __name__ == "__main__":
    from jupyter_mcp_server.__main__ import serve

    # If running with no args or just 'start'
    if len(sys.argv) == 1:
        sys.argv.extend(["start", "--transport", "stdio"])
    elif sys.argv[1] not in ("start", "connect", "stop", "--help"):
        # Wrap transparently into 'start'
        sys.argv.insert(1, "start")

    serve()
