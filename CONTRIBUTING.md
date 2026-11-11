# Contributing

Thanks for taking a look. This repository is a **production operations stack**, so contributions are judged on two things: does it make the lab safer, and does it stay reproducible?

## Ground rules

1. **No personal data.** Never commit real names, emails, SSH public keys, hostnames, tailnet IPs, webhook URLs or tokens. Use `student-1`, `100.64.0.11`, `user@example.com`.
2. **No new secrets paths.** Credentials belong in `secrets/` or `private/` (both git-ignored), never in code.
3. **Scripts must be idempotent.** Re-running a setup or hardening script should converge, not duplicate.
4. **Explain the failure mode.** If you add monitoring, describe what it detects and what it deliberately does *not*.

## Development

```bash
python3 -m py_compile ops-watch/*.py
python3 ops-watch/health_check.py --json
python3 ops-watch/analysis_llm.py --self-test   # needs agy/opencode/OpenRouter
```

There is no test suite yet; `scripts/hardening/*` and `labops/` have their own verification steps in their READMEs.

## Pull request checklist

- [ ] No secrets, emails or real IPs in the diff (`grep -rE '@|100\.64\.' <changed>`)
- [ ] Shell scripts pass `bash -n` and are idempotent
- [ ] Python compiles (`python3 -m py_compile`)
- [ ] Docs updated (README table, `docs/`, incident notes if relevant)
- [ ] Behaviour change is explained in the commit body (what, why, risk)

## Commit style

Conventional-ish, English, imperative:

```
feat(ops-watch): add reject workflow for tickets
fix(health): treat TCP RST as listener-down, not firewall-blocked
docs(incident): postmortem for 2026-11-11 mesh outage
```

## Reporting a vulnerability

Do **not** open a public issue. See [`SECURITY.md`](SECURITY.md).
