# Security review — 2026-11-12

Scope: repository (HEAD + all 13 commits), `ops-watch` application, and the GPU server runtime.
Method: git history scan (`git grep -o` across every rev), code review of state-changing paths, and read-only server inspection (`ss`, `sshd_config`, `dpkg`, package spool).

## Summary

| Severity | Open | Fixed/Mitigated |
|---|---|---|
| High | 1 | 2 |
| Medium | 3 | 2 |
| Low | 2 | 0 |
| Info | 1 | – |

No API keys, webhook URLs, Headscale pre-auth keys or private keys exist in Git history. The exposure is **personal data** (emails, SSH public keys) and a **third-party tunnel hostname**, plus runtime exposure on the host.

## Findings

### S1 · HIGH — Dashboard is unauthenticated and was bound to `0.0.0.0`
`ops-watch/dashboard.py` has no authentication and can:
- start/stop/restart containers (`/api/containers/control`)
- add users and provision Headscale (`/api/users/add`)
- create VPN pre-auth keys, expire/delete nodes
- trigger global lockdown and approve actions
- read `/api/metrics/users`, which returns **Jupyter tokens** and URLs

Bound to `0.0.0.0:23450`, any LAN/tailnet peer could perform all of the above.

**Mitigated:** default bind changed to `127.0.0.1` (`OPS_WATCH_BIND` to override). Verified on restart.
**Open:** authentication is still absent. Recommended: bearer-token or basic auth, or keep loopback-only permanently.

### S2 · HIGH — Real personal data in the repository and history
`labops/users.yaml` contained real student emails, full names and SSH public keys since commit `189fbd8` (2026-11-04). `ops-watch/WORKLOG.md` contained student/admin emails since `c5ea752`.

Commit scan (unique findings):

```
student3@example.com            labops/users.yaml        all commits since 189fbd8
student1@example.com   labops/users.yaml        c5ea752…
student2@example.com      labops/users.yaml        c5ea752…
student4@example.com           labops/users.yaml        189fbd8…
admin@example.com        ops-watch/WORKLOG.md     c5ea752…
```

**Fixed in HEAD:** emails replaced with `studentN@example.com`, SSH keys set to `null`, and the file marked as an anonymized seed (production source of truth remains `/etc/labops/users.yaml`).
**Still in history:** `git log -p` exposes them. A history rewrite is required before public release.

### S11 · HIGH — Live Jupyter token committed
`examples/jupyter-mcp/run_jupyter_mcp.py` and `test_mcp_client.py` contained the **admin JupyterLab token** (`REDACTED-TOKEN…`, 48 hex) as a default value, and `docs/ARCHITECTURE.md` contained token prefixes. The same token is returned by `/api/metrics/users`.

Present since `c5ea752`. **Fixed in HEAD:** read from `JUPYTER_TOKEN` / `<TOKEN>` placeholder. **Action:** rotate the Jupyter tokens for all four containers; the value is still in history.

### S3 · MEDIUM — ngrok tunnel hostname in tracked files
`headscale-tunnel.example` appeared in `labops/install.sh`, `labops/lib/labops_common.py`, `scripts/hardening/harden.sh`, `docs/ARCHITECTURE.md`, `docs/security-audit-2026-11-04.md` and `WORKLOG.md`.

**Fixed in HEAD:** now `LABOPS_HS_LOGIN_SERVER` / `LABOPS_NGROK_URL` with `<headscale-tunnel-host>` placeholder; docs updated.
**Action:** if that tunnel is still active, rotate/disable it — the hostname is in history.

### S4 · MEDIUM — Approval could report success without running anything
`ops_watch.approve()` replaced a missing binary with `echo "... Simulation ..."`, never checked the exit code, and still set `status='approved'`. The SSH host was also parsed from `shlex.split(source)[1]`, which breaks on `ssh -o …` and used `-o` as the host.

**Fixed:** missing binary → hard error (no simulation), exit code checked, `status='failed'` + `operator-approval-failed` worklog on failure, host parsed correctly. Verified both paths.

### S5 · MEDIUM — Docker-published ports bypass ufw
`ss -ltn` shows `0.0.0.0` listeners for `:80`, `:443`, `:8889`, `:8891`, `:9621`, `:8080` (docker-proxy). Docker's DNAT rules bypass ufw, so these are reachable from the LAN even though `ufw default deny incoming` is set.

**Open.** Jupyter (:8889/:8891) requires tokens and LightRAG (:9621) requires an API key, but the surface is larger than intended.
**Recommended:** bind published ports to `127.0.0.1` or the tailnet address; put admin-only services behind the ACL; `:8080` (DureClaw Headscale) should not be LAN-visible.

### S6 · MEDIUM — `sendfile`/inetd listening on `0.0.0.0:487` as root
```
/etc/inetd.conf: saft stream tcp nowait root /usr/sbin/tcpd /usr/sbin/sendfiled
ss: 0.0.0.0:487  users:(("inetd",pid=4464))
```
Package `sendfile` (SAFT), binary from 2024-04, spool with old users; `inetd.conf` was modified 2026-11-06. It is not referenced anywhere in this repository. `ts-input` accepts all tailnet traffic, so every tailnet peer can reach it.

**Open.** Not a backdoor (signed package), but unnecessary attack surface.
**Recommended:** `systemctl disable --now inetd` (or remove the `sendfile` package) unless deliberately used; verify no workflow depends on it.

### S7 · LOW — YAML injection in `add_user`
`system_metrics.add_user()` interpolates `full_name`, `email` and `notes` into `labops/users.yaml` without escaping quotes/newlines. Combined with S1, a crafted request could inject additional YAML keys (e.g., `role: admin`).

**Open.** Fix by JSON-encoding scalars or validating against a strict allowlist (`^[a-z0-9_-]+$`, email regex, single-line text).

### S8 · LOW — Ticket evidence is sent to third-party LLM providers
`analysis_llm.py` sends ticket evidence (usernames, IPs, file paths) to `agy`, `opencode` and OpenRouter without redaction.

**Open.** Recommended: redact usernames/IPs/home paths before prompting, or restrict to a local provider.

### S9 · INFO — Secrets exist on disk but are not committed
`secrets/discord-webhook.url`, `private/email-reissue-vpn-student1.txt` and `fix-control-plane.sh` contain a Discord webhook and Headscale pre-auth keys. All are git-ignored and absent from `git ls-files`, but they sit in the working directory.

**Action:** never share the working tree; rotate the keys if it was ever copied elsewhere; delete `fix-control-plane.sh` after use.

### S10 · INFO — Checks that passed
- `sshd`: `PermitRootLogin no`, `PasswordAuthentication no`, `AllowUsers martin student3 student1`, students restricted to `AllowTcpForwarding local` + `PermitOpen localhost`.
- `/etc/labops/discord-webhook.url` is `root:root 0600`.
- No world-writable binaries; the only world-writable files are a venv lock and node_modules from a user tool.
- Git history contains **no** `sk-*`, `hskey-*`, `ghp_*`, webhook URLs or `PRIVATE KEY` blocks.

## Remediation commands (history)

Run before making the repository public, then force-push and have collaborators re-clone:

```bash
pip install git-filter-repo
cat > /tmp/replace.txt <<'EOF'
student1@example.com==>student1@example.com
student2@example.com==>student2@example.com
student3@example.com==>student3@example.com
student4@example.com==>student4@example.com
admin@example.com==>admin@example.com
headscale-tunnel.example==>headscale-tunnel.example
REDACTED-JUPYTER-TOKEN==>REDACTED-JUPYTER-TOKEN
Student One==>Student One
Student Two==>Student Two
Student Three==>Student Three
EOF
git filter-repo --replace-text /tmp/replace.txt
git remote add origin https://github.com/baryonlabs/linux-machine-4090.git
git push --force --all && git push --force --tags
```

Rotate the Discord webhook and any pre-auth key that appeared in `WORKLOG.md` **regardless of the rewrite**.

## Verification

```bash
python3 -m py_compile ops-watch/*.py
python3 ops-watch/health_check.py --json
curl -s http://127.0.0.1:23450/api/status | python3 -m json.tool   # bind = loopback
git grep -nE 'gmail\.com|headscale-tunnel|hskey-|discord(app)?\.com/api/webhooks' $(git rev-list --all) -- . | head
```
