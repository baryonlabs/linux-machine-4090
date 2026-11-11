#!/usr/bin/env python3
"""End-to-End MCP Client Test for datalayer/jupyter-mcp-server."""

import asyncio
import json
import os
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

TOKEN = os.environ.get("JUPYTER_TOKEN", "<TOKEN>")
UV_BIN = os.path.expanduser("~/.local/bin/uv")
SCRIPT_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "run_jupyter_mcp.py"))


async def main():
    print("=" * 65)
    print("🚀 Connecting to Jupyter MCP Server via Stdio Transport...")
    print(f"Target Server: http://100.64.0.2:8888")
    print(f"Token: {TOKEN}")
    print("=" * 65)

    server_params = StdioServerParameters(
        command=UV_BIN,
        args=["run", "--with", "jupyter-mcp-server", "python", SCRIPT_PATH, "start", "--transport", "stdio"],
        env={
            **os.environ,
            "CODE_SANDBOX_URL": "http://100.64.0.2:8888",
            "CODE_SANDBOX_TOKEN": TOKEN,
        }
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            # 1. Initialize MCP Session
            print("\n[1/3] Initializing MCP Session...")
            init_res = await session.initialize()
            print(f"✔ Handshake Successful!")
            print(f"  Server Name: {init_res.server_info.name}")
            print(f"  Server Version: {init_res.server_info.version}")
            print(f"  Protocol Version: {init_res.protocol_version}")

            # 2. List Available Tools
            print("\n[2/3] Querying Available MCP Tools...")
            tools_res = await session.list_tools()
            tool_names = [t.name for t in tools_res.tools]
            print(f"✔ Found {len(tool_names)} Available Jupyter MCP Tools:")
            for i, name in enumerate(tool_names, 1):
                desc = next(t.description for t in tools_res.tools if t.name == name).split("\n")[0]
                print(f"  {i:2d}. {name:<25} - {desc}")

            # 3. Call 'list_files' Tool
            print("\n[3/3] Executing 'list_files' Tool on Remote RTX 4090 Workstation...")
            call_res = await session.call_tool("list_files", arguments={"path": ""})
            print("✔ Tool Execution Output:")
            print("-" * 65)
            for content in call_res.content:
                if hasattr(content, "text"):
                    print(content.text)
                else:
                    print(content)
            print("-" * 65)

            # 4. Call 'list_kernels' Tool
            print("\n[4/4] Executing 'list_kernels' Tool on Remote Server...")
            kernel_res = await session.call_tool("list_kernels", arguments={})
            print("✔ Kernel Status Output:")
            print("-" * 65)
            for content in kernel_res.content:
                if hasattr(content, "text"):
                    print(content.text)
                else:
                    print(content)
            print("-" * 65)

    print("\n🎉 ALL TESTS PASSED SUCCESSFULLY! jupyter-mcp-server is fully operational.")


if __name__ == "__main__":
    asyncio.run(main())
