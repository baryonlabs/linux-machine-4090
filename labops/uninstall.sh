#!/usr/bin/env bash
# labops uninstaller.   sudo bash ~/labops/uninstall.sh [--purge] [--purge-packages]
#   default           stop/remove units, binaries, falco/audit rule files; KEEP data (/var/lib/labops, /etc/labops, logs)
#   --purge           also delete /etc/labops, /var/lib/labops (GPU db, requests), /var/log/labops
#   --purge-packages  also apt-get remove falco (+ its apt repo); auditd/acct/lynis are left installed (harmless)
# Does not touch accounts, sshd config, Headscale or the CVE/egress firewall services.
# Removes the labops pam_exec line from /etc/pam.d/sshd.
set -uo pipefail
export LC_ALL=C
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
PURGE=0; PURGE_PKG=0
for a in "$@"; do case "$a" in --purge) PURGE=1;; --purge-packages) PURGE_PKG=1;; *) echo "unknown $a"; exit 2;; esac; done

UNITS="labops-gpu-collect.timer labops-daily.timer labops-weekly-lynis.timer labops-audit-alert.timer labops-reqd.socket
labops-executor.path labops-executor.timer labops-fw.service falcosidekick.service"
for u in $UNITS; do systemctl disable --now "$u" 2>/dev/null; done
for f in labops-gpu-collect labops-daily labops-weekly-lynis labops-audit-alert labops-executor; do
  rm -f /etc/systemd/system/$f.service /etc/systemd/system/$f.timer /etc/systemd/system/$f.path
done
rm -f /etc/systemd/system/labops-reqd.socket /etc/systemd/system/labops-reqd@.service \
      /etc/systemd/system/labops-fw.service /etc/systemd/system/falcosidekick.service
systemctl daemon-reload

rm -f /etc/audit/rules.d/50-labops.rules /etc/audit/rules.d/51-labops-students.rules /etc/audit/rules.d/52-labops-setuid.rules
command -v augenrules >/dev/null && augenrules --load >/dev/null 2>&1
[ -f /var/backups/labops/auditd.conf.orig ] && cp -a /var/backups/labops/auditd.conf.orig /etc/audit/auditd.conf \
  && systemctl restart auditd 2>/dev/null

rm -f /etc/falco/config.d/labops.yaml /etc/falco/rules.d/labops_rules.yaml /etc/falco/rules.d/labops_00_students.yaml
systemctl is-active -q falco-modern-bpf && systemctl restart falco-modern-bpf
rm -f /usr/local/bin/falcosidekick /etc/labops/falcosidekick.env /etc/labops/falcosidekick.version
rm -f /usr/local/sbin/labctl /usr/local/bin/labreq /usr/local/sbin/labops-notify /etc/logrotate.d/labops
rm -rf /opt/labops

if [ $PURGE_PKG = 1 ]; then
  systemctl disable --now falco-modern-bpf 2>/dev/null
  apt-get remove -y falco
  rm -f /etc/apt/sources.list.d/falcosecurity.list /usr/share/keyrings/falco-archive-keyring.gpg
fi
if [ $PURGE = 1 ]; then
  rm -rf /etc/labops /var/lib/labops /var/log/labops
  id labops >/dev/null 2>&1 && userdel labops
else
  echo "kept: /etc/labops (registry, webhook), /var/lib/labops (gpu.db, requests, lynis), /var/log/labops"
fi
echo "labops removed."

# pam_exec session hook
if grep -qF "labops-session-hook" /etc/pam.d/sshd 2>/dev/null; then
  sed -i '/# labops: Discord notice on SSH session open\/close/d; /labops-session-hook/d' /etc/pam.d/sshd
  echo "removed labops pam_exec line from /etc/pam.d/sshd"
fi
