#!/usr/bin/env bash
# Deploy narrowly scoped alert-noise fixes for normal student SSH login paths.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FALCO_SOURCE="$ROOT_DIR/falco/labops_rules.yaml"
FALCO_TARGET=/etc/falco/rules.d/labops_rules.yaml
AUDIT_SOURCE="$ROOT_DIR/audit/50-labops.rules"
AUDIT_TARGET=/etc/audit/rules.d/50-labops.rules
STAMP="$(date +%Y%m%d%H%M%S)"

[[ $EUID -eq 0 ]] || { echo "Run with: sudo bash $0" >&2; exit 1; }
[[ -r $FALCO_SOURCE && -r $AUDIT_SOURCE ]] || { echo "Run from the labops source directory" >&2; exit 1; }

# Validate before replacing the active Falco file.
falco -V /etc/falco/falco_rules.yaml \
  -V /etc/falco/rules.d/labops_00_students.yaml \
  -V "$FALCO_SOURCE"

cp -a "$FALCO_TARGET" "$FALCO_TARGET.bak.$STAMP"
install -m 0644 "$FALCO_SOURCE" "$FALCO_TARGET"
install -m 0755 "$ROOT_DIR/bin/labops-audit-alert" /opt/labops/bin/labops-audit-alert

# Attribute shadow reads to the actual non-root caller, not root sshd/PAM helpers
# that retain a student's audit loginuid during authentication/session setup.
for f in "$AUDIT_SOURCE" "$AUDIT_TARGET"; do
  sed -i '/-k shadow_read$/ { /-F uid>=1000/! s/ -k shadow_read$/ -F uid>=1000 -k shadow_read/; }' "$f"
done

augenrules --load
systemctl restart falco-modern-bpf
systemctl is-active --quiet falco-modern-bpf
echo "Applied: Falco active; audit shadow_read limited to non-root callers."
