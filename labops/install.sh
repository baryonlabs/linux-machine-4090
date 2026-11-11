#!/usr/bin/env bash
# labops installer — idempotent. Run on the GPU server:   sudo bash ~/labops/install.sh
#   --no-falco      skip Falco + falcosidekick
#   --no-selftest   skip the end-to-end detection tests (they run harmless probes as a student account)
# Never runs apt upgrade; aborts if installing the packages would upgrade/remove NVIDIA/kernel packages.
set -uo pipefail
export LC_ALL=C DEBIAN_FRONTEND=noninteractive
[ "$(id -u)" = 0 ] || { echo "run with: sudo bash $0"; exit 1; }

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ADMIN=martin
TEST_STUDENT=student1
SIDEKICK_FALLBACK=2.35.1
WITH_FALCO=1; SELFTEST=1
for a in "$@"; do case "$a" in --no-falco) WITH_FALCO=0;; --no-selftest) SELFTEST=0;; *) echo "unknown option $a"; exit 2;; esac; done

declare -a RESULTS=()
pass(){ RESULTS+=("PASS  $*"); echo "  PASS $*"; }
fail(){ RESULTS+=("FAIL  $*"); echo "  FAIL $*"; }
warn(){ RESULTS+=("WARN  $*"); echo "  WARN $*"; }
check(){ local d="$1"; shift; if "$@" >/dev/null 2>&1; then pass "$d"; else fail "$d"; fi; }
step(){ echo; echo "===== $*"; }

[ -f "$SRC/labctl" ] && [ -d "$SRC/bin" ] || { echo "run from the labops/ directory copy"; exit 1; }
ADMIN_GROUP=$(id -gn "$ADMIN")

# ------------------------------------------------------------------------------------------------ packages
step "packages (auditd acct lynis sqlite3$([ $WITH_FALCO = 1 ] && echo ' falco'))"
DKMS_BEFORE=$(dpkg-query -W -f='${Status}' dkms 2>/dev/null | grep -c "ok installed" || true)
if [ $WITH_FALCO = 1 ] && [ ! -f /etc/apt/sources.list.d/falcosecurity.list ]; then
  install -d -m 755 /usr/share/keyrings
  if curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | gpg --dearmor --yes -o /usr/share/keyrings/falco-archive-keyring.gpg; then
    echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" \
      > /etc/apt/sources.list.d/falcosecurity.list
  else
    fail "falco apt key download"; WITH_FALCO=0
  fi
fi
apt-get update -qq || warn "apt-get update had errors (continuing with cached lists)"
PKGS="auditd acct lynis sqlite3"; [ $WITH_FALCO = 1 ] && PKGS="$PKGS falco"
SIM=$(apt-get install -s --no-install-recommends $PKGS 2>&1)
if echo "$SIM" | grep -qE '^Remv '; then
  echo "$SIM" | grep -E '^Remv '; echo "!!! installing would REMOVE packages — aborting"; exit 1
fi
if echo "$SIM" | grep -E '^Inst \S+ \[' | grep -qiE 'nvidia|cuda|^Inst linux-'; then
  echo "$SIM" | grep -E '^Inst \S+ \[' | grep -iE 'nvidia|cuda|linux-'
  echo "!!! installing would UPGRADE NVIDIA/kernel packages (driver/library mismatch before reboot) — aborting"; exit 1
fi
UPG=$(echo "$SIM" | grep -cE '^Inst \S+ \[' || true)
[ "$UPG" -gt 0 ] && { echo "note: $UPG dependency upgrade(s):"; echo "$SIM" | grep -E '^Inst \S+ \[' | sed 's/^/    /'; }
FALCO_FRONTEND=noninteractive FALCO_DRIVER_CHOICE=modern_ebpf FALCOCTL_ENABLED=no \
  apt-get install -y -qq --no-install-recommends $PKGS >/tmp/labops-apt.log 2>&1 \
  || { tail -20 /tmp/labops-apt.log; fail "apt-get install $PKGS"; }
for p in $PKGS; do check "package $p installed" dpkg-query -W -f='${Status}' "$p"; done
DKMS_AFTER=$(dpkg-query -W -f='${Status}' dkms 2>/dev/null | grep -c "ok installed" || true)
[ "$DKMS_AFTER" -le "$DKMS_BEFORE" ] && pass "no dkms package added by this installer" || fail "dkms got installed"

# ------------------------------------------------------------------------------------------------ files
step "deploy /opt/labops, /etc/labops"
id labops >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin labops
install -d -m 755 /opt/labops /opt/labops/bin /opt/labops/lib /opt/labops/falco /opt/labops/audit
install -m 755 "$SRC/labctl" /opt/labops/labctl
find "$SRC/bin" -maxdepth 1 -type f -exec install -m 755 {} /opt/labops/bin/ \;
rm -rf /opt/labops/bin/__pycache__
install -m 644 "$SRC"/lib/*.py /opt/labops/lib/
install -m 644 "$SRC"/falco/*.yaml /opt/labops/falco/
install -m 644 "$SRC"/audit/*.rules /opt/labops/audit/
install -m 644 "$SRC/users.yaml" /opt/labops/users.yaml.seed
rm -rf /opt/labops/lib/__pycache__
ln -sfn /opt/labops/labctl /usr/local/sbin/labctl
ln -sfn /opt/labops/bin/labreq /usr/local/bin/labreq
ln -sfn /opt/labops/bin/labops-notify /usr/local/sbin/labops-notify

install -d -m 755 /etc/labops
[ -f /etc/labops/users.yaml ] || install -m 644 "$SRC/users.yaml" /etc/labops/users.yaml
if [ ! -f /etc/labops/labops.conf ]; then
  cat > /etc/labops/labops.conf <<CONF
# labops configuration (KEY=VALUE). Defaults live in /opt/labops/lib/labops_common.py.
ADMIN_USER=$ADMIN
SSH_PORT=2322
SSH_HOST=100.64.0.2
DATA_ROOT=/mnt/data/users
HS_CONTAINER=headscale
HS_ACL=/home/$ADMIN/headscale/config/acl.hujson
HS_LOGIN_SERVER=${LABOPS_HS_LOGIN_SERVER:-https://<headscale-tunnel-host>}
APT_ALLOWED_HOSTS=archive.ubuntu.com,security.ubuntu.com,kr.archive.ubuntu.com,mirror.kakao.com
REQ_MAX_PENDING=5
REQ_EXPIRY_DAYS=7
REQ_EXTRA_UIDS=
CONF
fi
HOME_HOOK=/home/$ADMIN/.labops-discord-webhook.url
if [ -f "$HOME_HOOK" ]; then
  install -m 600 -o root -g root "$HOME_HOOK" /etc/labops/discord-webhook.url && rm -f "$HOME_HOOK"
fi
if [ -f /etc/labops/discord-webhook.url ]; then
  chown root:root /etc/labops/discord-webhook.url; chmod 600 /etc/labops/discord-webhook.url
  pass "webhook at /etc/labops/discord-webhook.url (root 600), home copy removed: $([ -e "$HOME_HOOK" ] && echo no || echo yes)"
else
  fail "no Discord webhook (place it at /etc/labops/discord-webhook.url, root:root 600)"
fi

install -d -m 755 -o root -g root /var/lib/labops
install -d -m 700 /var/lib/labops/audit-checkpoints /var/backups/labops
install -d -m 750 /var/lib/labops/lynis
install -d -m 2750 -o labops -g "$ADMIN_GROUP" /var/lib/labops/requests
[ -f /var/lib/labops/requests/.lock ] || install -m 600 -o labops -g labops /dev/null /var/lib/labops/requests/.lock
chown labops:labops /var/lib/labops/requests/.lock; chmod 600 /var/lib/labops/requests/.lock
install -d -m 700 -o "$ADMIN" -g "$ADMIN_GROUP" /var/lib/labops/decisions /var/lib/labops/decisions.tmp
install -d -m 700 -o root -g root /var/lib/labops/decisions-processed
install -d -m 751 -o root -g adm /var/log/labops
[ -f /var/log/labops/requests.log ] || install -m 640 -o labops -g adm /dev/null /var/log/labops/requests.log
cat > /etc/logrotate.d/labops <<'LR'
/var/log/labops/*.log {
    weekly
    rotate 52
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
LR
check "/opt/labops deployed + labctl symlink" test -x /usr/local/sbin/labctl

# ------------------------------------------------------------------------------------------------ auditd
step "auditd (rules + rotation) and process accounting"
AC=/etc/audit/auditd.conf
if [ -f "$AC" ]; then
  [ -f /var/backups/labops/auditd.conf.orig ] || cp -a "$AC" /var/backups/labops/auditd.conf.orig
  setkv(){ if grep -qE "^\s*$1\s*=" "$AC"; then sed -i -E "s|^\s*$1\s*=.*|$1 = $2|" "$AC"; else echo "$1 = $2" >> "$AC"; fi; }
  setkv log_format ENRICHED
  setkv max_log_file 50
  setkv num_logs 10
  setkv max_log_file_action ROTATE
  setkv space_left 2048
  setkv space_left_action SYSLOG
  setkv admin_space_left 1024
  setkv admin_space_left_action SUSPEND
  setkv disk_full_action SUSPEND
  setkv disk_error_action SYSLOG
fi
install -m 640 "$SRC/audit/50-labops.rules" /etc/audit/rules.d/50-labops.rules
/usr/local/sbin/labctl audit-rules || warn "labctl audit-rules reported errors"
systemctl enable auditd >/dev/null 2>&1
systemctl restart auditd 2>/dev/null || service auditd restart
sleep 2
augenrules --check >/dev/null 2>&1; augenrules --load >/tmp/labops-augenrules.log 2>&1 || { cat /tmp/labops-augenrules.log; fail "augenrules --load"; }
check "auditd active" systemctl is-active auditd
NRULES=$(auditctl -l 2>/dev/null | grep -cE 'key=(student_exec|setuid_exec|priv_esc|identity|shadow_read|cve_2026_98432|ptrace|modules)' || true)
[ "$NRULES" -gt 10 ] && pass "audit rules loaded ($NRULES labops rules)" || fail "audit rules loaded ($NRULES)"
grep -qE 'a1=(0x)?0 -F a2=(0x)?4' <<<"$(auditctl -l 2>/dev/null)" && pass "CVE-2026-98432 setsockopt(IP_OPTIONS) audit rule" || fail "CVE audit rule"
systemctl enable --now acct >/dev/null 2>&1 || true
check "process accounting (acct) active" systemctl is-active acct

# ------------------------------------------------------------------------------------------------ falco + sidekick
if [ $WITH_FALCO = 1 ]; then
  step "Falco (modern_ebpf) + falcosidekick -> Discord"
  install -d -m 755 /etc/falco/config.d /etc/falco/rules.d
  install -m 644 "$SRC/falco/labops-falco.yaml" /etc/falco/config.d/labops.yaml
  install -m 644 "$SRC/falco/labops_rules.yaml" /etc/falco/rules.d/labops_rules.yaml
  [ -f /etc/falco/rules.d/labops_00_students.yaml ] || /usr/local/sbin/labctl audit-rules >/dev/null 2>&1 || true
  systemctl mask --now falcoctl-artifact-follow.service >/dev/null 2>&1 || true   # pin rules to the package version
  if falco -V /etc/falco/falco_rules.yaml -V /etc/falco/rules.d/labops_00_students.yaml -V /etc/falco/rules.d/labops_rules.yaml >/tmp/labops-falco-V.log 2>&1; then
    pass "falco rule validation"
  else
    tail -20 /tmp/labops-falco-V.log; fail "falco rule validation"
  fi

  # falcosidekick binary (systemd-managed), checksum-verified
  VER=$(curl -fsSL -m 15 https://api.github.com/repos/falcosecurity/falcosidekick/releases/latest 2>/dev/null \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["tag_name"])' 2>/dev/null || echo "$SIDEKICK_FALLBACK")
  if [ "$(cat /etc/labops/falcosidekick.version 2>/dev/null)" != "$VER" ] || [ ! -x /usr/local/bin/falcosidekick ]; then
    T=$(mktemp -d)
    BASE="https://github.com/falcosecurity/falcosidekick/releases/download/$VER"
    if curl -fsSL -m 120 -o "$T/fs.tgz" "$BASE/falcosidekick_${VER}_linux_amd64.tar.gz" && curl -fsSL -m 30 -o "$T/sums" "$BASE/checksums.txt"; then
      WANT=$(grep " falcosidekick_${VER}_linux_amd64.tar.gz\$" "$T/sums" | awk '{print $1}')
      HAVE=$(sha256sum "$T/fs.tgz" | awk '{print $1}')
      if [ -n "$WANT" ] && [ "$WANT" = "$HAVE" ]; then
        tar -xzf "$T/fs.tgz" -C "$T" falcosidekick && install -m 755 "$T/falcosidekick" /usr/local/bin/falcosidekick \
          && echo "$VER" > /etc/labops/falcosidekick.version
        pass "falcosidekick $VER (sha256 verified)"
      else
        fail "falcosidekick checksum mismatch"
      fi
    else
      fail "falcosidekick download"
    fi
    rm -rf "$T"
  else
    pass "falcosidekick $VER already installed"
  fi
  if [ -f /etc/labops/discord-webhook.url ]; then
    umask 077
    { echo "LISTENADDRESS=127.0.0.1"; echo "LISTENPORT=2801"
      echo "DISCORD_WEBHOOKURL=$(cat /etc/labops/discord-webhook.url)"
      echo "DISCORD_MINIMUMPRIORITY=warning"
      echo "CUSTOMFIELDS=host:$(hostname)"; } > /etc/labops/falcosidekick.env
    umask 022
    chmod 600 /etc/labops/falcosidekick.env
  fi
fi

# ------------------------------------------------------------------------------------------------ ssh session notify (pam_exec)
step "SSH login/logout -> Discord (pam_exec, optional = never blocks login)"
PAM_LINE="session optional pam_exec.so quiet /opt/labops/bin/labops-session-hook"
if ! grep -qF "labops-session-hook" /etc/pam.d/sshd; then
  cp -a /etc/pam.d/sshd "/etc/pam.d/.sshd.labops-bak.$(date +%Y%m%d%H%M%S)"
  printf '\n# labops: Discord notice on SSH session open/close\n%s\n' "$PAM_LINE" >> /etc/pam.d/sshd
fi
grep -qF "$PAM_LINE" /etc/pam.d/sshd && pass "pam_exec session hook in /etc/pam.d/sshd" || fail "pam_exec session hook"
install -d -m 700 /run/labops/sessions 2>/dev/null || true

# ------------------------------------------------------------------------------------------------ systemd
step "systemd units"
install -m 644 "$SRC"/systemd/*.service "$SRC"/systemd/*.timer "$SRC"/systemd/*.socket "$SRC"/systemd/*.path /etc/systemd/system/
systemctl daemon-reload
UNITS="labops-gpu-collect.timer labops-daily.timer labops-weekly-lynis.timer labops-audit-alert.timer labops-reqd.socket labops-executor.path labops-executor.timer labops-fw.service"
[ $WITH_FALCO = 1 ] && UNITS="$UNITS falcosidekick.service"
for u in $UNITS; do systemctl enable --now "$u" >/dev/null 2>&1; check "$u enabled+active" systemctl is-active "$u"; done
systemctl restart labops-fw.service
iptables -C OUTPUT -o lo -p tcp --dport 2801 -m owner ! --uid-owner 0 -j REJECT 2>/dev/null && pass "falcosidekick port 2801 root-only" || fail "labops-fw rule"

if [ $WITH_FALCO = 1 ]; then
  systemctl enable falco-modern-bpf.service >/dev/null 2>&1
  systemctl restart falco-modern-bpf.service
  sleep 25
  check "falco-modern-bpf active" systemctl is-active falco-modern-bpf
  # wait until the probe is attached (also makes the self-test below meaningful)
  for _i in $(seq 1 30); do grep -qi "modern BPF probe" <<<"$(journalctl -u falco-modern-bpf --since "-2min" -o cat 2>/dev/null)" && break; sleep 2; done
  grep -qiE "modern (BPF|eBPF) probe|modern_ebpf" <<<"$(journalctl -u falco-modern-bpf --since "-2min" -o cat 2>/dev/null)" \
    && pass "falco uses modern_ebpf (no kernel module)" || warn "could not confirm modern_ebpf from journal"
  lsmod | grep -qE '^falco' && fail "falco kernel module loaded" || pass "no falco kernel module"
  check "falcosidekick listening on 127.0.0.1:2801" bash -c "ss -ltn | grep -q '127.0.0.1:2801'"
  PID=$(systemctl show -p MainPID --value falco-modern-bpf)
  if [ "${PID:-0}" -gt 0 ]; then
    read -r RSS CPU < <(ps -o rss=,pcpu= -p "$PID")
    MEM=$(systemctl show -p MemoryCurrent --value falco-modern-bpf)
    pass "falco overhead: RSS $((RSS/1024)) MiB, CPU ${CPU}% (avg since start), cgroup mem $((MEM/1048576)) MiB"
  fi
  SPID=$(systemctl show -p MainPID --value falcosidekick)
  [ "${SPID:-0}" -gt 0 ] && pass "falcosidekick RSS $(( $(ps -o rss= -p "$SPID") / 1024 )) MiB"
fi

# ------------------------------------------------------------------------------------------------ first runs
step "first runs"
systemctl start labops-gpu-collect.service && pass "GPU collector run" || fail "GPU collector run"
[ -f /var/lib/labops/gpu.db ] && { chgrp adm /var/lib/labops/gpu.db; chmod 640 /var/lib/labops/gpu.db; }
check "gpu.db has a gpu sample" bash -c "[ \$(sqlite3 /var/lib/labops/gpu.db 'select count(*) from gpu') -gt 0 ]"
systemctl start labops-executor.service && pass "executor run" || fail "executor run"
if id "$TEST_STUDENT" >/dev/null 2>&1; then
  OUT=$(sudo -u "$TEST_STUDENT" -H /usr/local/bin/labreq status 2>&1)
  echo "$OUT" | grep -qE "no requests|^#" && pass "labreq reachable as $TEST_STUDENT (SO_PEERCRED)" || fail "labreq as $TEST_STUDENT: $OUT"
fi
OUT=$(sudo -u "$ADMIN" -H /usr/local/bin/labreq status 2>&1)
echo "$OUT" | grep -q "only members of the students group" && pass "labreq refuses non-students ($ADMIN)" || warn "labreq as $ADMIN: $OUT"
check "labctl requests as $ADMIN (no sudo)" sudo -u "$ADMIN" -H /usr/local/sbin/labctl requests

/usr/local/sbin/labops-notify "labops installed on **$(hostname)** ($(date '+%F %T %Z')) — monitoring active. A self-test may produce a few WARNING/CRITICAL test alerts from $TEST_STUDENT in the next minutes." \
  && pass "Discord test message" || fail "Discord test message"
if [ $WITH_FALCO = 1 ] && systemctl is-active -q falcosidekick; then
  curl -fsS -m 10 -o /dev/null -H 'Content-Type: application/json' \
    -d "{\"output\":\"labops falcosidekick test from $(hostname) (ignore)\",\"priority\":\"Warning\",\"rule\":\"labops install test\",\"time\":\"$(date -u +%Y-%m-%dT%H:%M:%S.000000000Z)\",\"output_fields\":{}}" \
    http://127.0.0.1:2801/ && pass "falcosidekick -> Discord test event" || fail "falcosidekick test event"
fi

# ------------------------------------------------------------------------------------------------ self-test
if [ $SELFTEST = 1 ] && id "$TEST_STUDENT" >/dev/null 2>&1; then
  step "self-test as $TEST_STUDENT (harmless probes)"
  T0=$(date '+%x %X')
  SK0=$(journalctl -u falcosidekick -o cat --no-pager 2>/dev/null | grep -c "Discord - POST OK" || true)
  sudo -u "$TEST_STUDENT" -H bash -s <<'T' >/dev/null 2>&1
cat /etc/shadow
ls /home/martin
python3 -c "import socket; s=socket.socket(); s.setsockopt(socket.IPPROTO_IP, socket.IP_OPTIONS, b'\x01\x01\x01\x00'); s.close()"
true
T
  sleep 8
  # shellcheck disable=SC2086
  # execve rules match the audit loginuid (auid), which `sudo -u` keeps as the admin's -> cannot be
  # exercised from this installer; verify after the student's first real SSH login with:
  #   sudo ausearch -k student_exec -ua $(id -u $TEST_STUDENT) | head
  N_EXEC=$(grep -c "auid=$(id -u $TEST_STUDENT) " /etc/audit/rules.d/51-labops-students.rules 2>/dev/null || true)
  [ "${N_EXEC:-0}" -gt 0 ] && warn "auditd: student execve rule present (live test needs a real student SSH login)" || fail "auditd: student execve rule missing"
  # shellcheck disable=SC2086
  ausearch --input-logs -k shadow_read --start $T0 >/dev/null 2>&1 && pass "auditd: /etc/shadow read attempt logged" || fail "auditd: shadow_read"
  # shellcheck disable=SC2086
  ausearch --input-logs -k cve_2026_98432 --start $T0 >/dev/null 2>&1 && pass "auditd: setsockopt(IP_OPTIONS) logged" || fail "auditd: cve_2026_98432"
  if [ $WITH_FALCO = 1 ]; then
    # falco-modern-bpf.service has StandardOutput=null -> alerts are only visible via falcosidekick
    SK1=$(journalctl -u falcosidekick -o cat --no-pager 2>/dev/null | grep -c "Discord - POST OK" || true)
    [ $((SK1 - SK0)) -ge 2 ] && pass "falco: student probes detected and delivered to Discord ($((SK1 - SK0)) alerts)" \
      || fail "falco: student probes not delivered (sidekick POST OK delta $((SK1 - SK0)))"
  fi
  systemctl start labops-audit-alert.service && pass "audit-alert run (posts the CVE test event)" || fail "audit-alert run"
fi

# ------------------------------------------------------------------------------------------------ summary
step "labctl sync preview (nothing applied — run 'sudo labctl sync' yourself after reviewing)"
/usr/local/sbin/labctl --dry-run sync 2>&1 | grep -E '\[plan\]|!!' | head -40 || true

echo; echo "================ CHECKLIST ================"
printf '%s\n' "${RESULTS[@]}"
NF=$(printf '%s\n' "${RESULTS[@]}" | grep -c '^FAIL' || true)
echo "==========================================="
echo "FAIL: $NF   (logs: /tmp/labops-apt.log, journalctl -u falco-modern-bpf -u falcosidekick -u labops-*)"
[ "$NF" = 0 ]
