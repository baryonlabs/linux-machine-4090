# Security Policy

## Reporting a vulnerability

Please report security issues **privately** — do not open a public issue or PR.

- Use GitHub's *Security → Report a vulnerability* on this repository, or
- Contact the maintainers at Baryon Labs directly.

Include: affected component, reproduction steps, impact, and whether any secret or personal data was exposed. We aim to acknowledge within 3 business days.

## Scope

In scope:

- `ops-watch/` (dashboard, API, LLM chain, health checks)
- `headscale/` (ACL, key issuance)
- `labops/` (account lifecycle, privileged request executor)
- `scripts/hardening/` (firewall, SSH, CVE mitigation)
- Deployment defaults documented in `docs/ARCHITECTURE.md`

Out of scope: findings that require physical access to the GPU host, or that depend on deliberately weakening the documented defaults.

## Handling secrets

This project assumes:

- `secrets/`, `private/`, `emails/`, `state/` are **never committed** (see `.gitignore`).
- Webhook URLs and API keys live in root-owned files on the host (`/etc/labops/...`, mode `600`) or in the operator's keychain.
- The LLM chain resolves keys at runtime and never writes them to the worklog.

If you find a secret in the Git history, report it privately and rotate it first — assume it is compromised.

## Hardening baseline

Deployments are expected to run:

- key-only SSH on a non-standard port with `AllowUsers`
- `ufw default deny incoming` + `student-egress` for untrusted accounts
- auditd and Falco enabled
- kernel CVE mitigations applied until the fixed kernel is installed

See [`docs/security-audit-2026-11-04.md`](docs/security-audit-2026-11-04.md) for the last full audit.
