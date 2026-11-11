# ops-watch

Shared-server operator assistant with **NVIDIA Auto-Ontology**, **agent memory**, and **explicit allowlisted approvals**.

It polls approved read-only log commands, records findings, correlates with system background and historical precedents, and creates approval tickets. It **never runs a remote mutation or unauthorized command during scanning**.

## Workflow

```text
read-only scan -> finding -> approval ticket -> Antigravity triage -> explicit approve -> allowlisted action
                                     ^
                                     |
           +-------------------------+-------------------------+
           |                                                   |
           v                                                   v
  [Operational Memory & Precedents]                 [NVIDIA Auto-Ontology]
   - Past decisions & approvals                      - Semantic glossary terms
   - Operator notes & rationale                      - Certified baseline patterns
```

The program is deliberately not an autonomous root agent. A ticket stores an exact action name and arguments; `approve` rejects anything outside the allowlist.

## Quick start

```bash
cd ops-watch

# 1. Scan for new security findings (read-only)
python3 ops_watch.py scan

# 2. View pending tickets
python3 ops_watch.py pending

# 3. Analyze ticket with Antigravity LLM, Auto-Ontology & Memory
python3 ops_watch.py analyze 1

# 4. Record operator rationale or review note into memory
python3 ops_watch.py note 1 "Verified: legitimate student access"

# 5. Explicitly approve an allowlisted investigation action
python3 ops_watch.py approve 1

# 6. View durable worklog or export to WORKLOG.md
python3 ops_watch.py worklog
python3 ops_watch.py worklog --export

# 7. Search agent memory & historical precedents
python3 ops_watch.py memory "credential"

# 8. Check Auto-Ontology connection status and export Ossie model
python3 ops_watch.py ontology
python3 ops_watch.py ontology --export-ossie
```

## Log Source Configuration

Set `OPS_WATCH_SOURCE` to a read-only command that prints logs. The default is a local `journalctl` query. For the GPU server, run the watcher from an account allowed to read its journal:

```bash
export OPS_WATCH_SOURCE='ssh linux-builder journalctl -u falco-modern-bpf -u ssh --since "-5 min" -o cat --no-pager'
```

## NVIDIA Auto-Ontology Integration

ops-watch integrates with [NVIDIA Auto-Ontology](https://github.com/NVIDIA/auto-ontology):
- **Agent Skills**: `nvidia-ontology-setup`, `nvidia-ontology-management`, and `nvidia-ontology-query` are installed into `.agents/skills` and `.gemini/skills`.
- **Semantic Layer**: Uses certified operational terms (`StudentResearcher`, `FalcoAlert`, `AuditdRecord`, etc.) and baseline patterns.
- **Remote Bridge**: Connects to Auto-Ontology on `AUTO_ONTOLOGY_API_URL` (default: `http://localhost:3000`) and FastMCP server (`http://localhost:3003/mcp`), with transparent fallback to local semantic definitions.

## Deployment

`systemd/ops-watch.service` and `.timer` provide five-minute scans. Install only after choosing the host and Discord/approval channel; the service intentionally has no sudo or remote-write capability.
