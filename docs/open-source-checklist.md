# Open-source readiness checklist

This repository is currently **private**. Before making it public, complete every item below.

## 1. Secrets

- [ ] `secrets/`, `private/`, `emails/`, `state/`, `*.log` are absent from the working tree **and** from Git history
- [ ] Run `gitleaks detect --no-git=false` (or `gh secret-scanning`) and clear all findings
- [ ] Rotate anything that was ever committed: Discord webhook, Headscale pre-auth keys, ngrok URL, API keys
- [ ] Verify `grep -rE 'sk-[A-Za-z0-9]{12,}|hskey-|ghp_|discord(app)?\.com/api/webhooks' .` returns nothing

## 2. Personal data

- [ ] `labops/users.yaml` → replace real names, emails and SSH public keys with examples
- [ ] `scripts/hardening/harden.sh` → remove the ngrok URL, real usernames and hostnames
- [ ] `headscale/acl.hujson` → replace user/group names
- [ ] `docs/` incident notes and worklog → names, IPs, hostnames anonymized
- [ ] Diagrams (`docs/architecture.png` / `.html`) → identifiers already anonymized; re-check after edits

## 3. Configuration

- [ ] `100.64.0.2` and other real tailnet IPs replaced with documentation values (or explicitly marked as examples)
- [ ] Ports and versions reviewed for accuracy
- [ ] `OPS_WATCH_*` defaults are safe for a fresh install

## 4. Repository metadata

- [ ] `LICENSE` added (Apache-2.0 or MIT recommended)
- [ ] `SECURITY.md` and `CONTRIBUTING.md` present
- [ ] Description and topics set (e.g. `gpu`, `headscale`, `observability`, `llm`, `labops`)
- [ ] CI: `python3 -m py_compile`, `bash -n`, secret scan
- [ ] A short 60-second demo (GIF or terminal recording) in the README

## 5. Content

- [ ] README quick-start verified on a clean machine
- [ ] Incident postmortems reviewed for sensitive operational detail
- [ ] Third-party licenses/attributions checked (Headscale, Falco, Tailscale, icons)

## 6. Maintainers

- [ ] Decide the public name and repository slug
- [ ] Enable Discussions / issue templates
- [ ] Add a CODEOWNERS entry and a response policy for security reports
