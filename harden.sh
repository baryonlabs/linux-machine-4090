#!/usr/bin/env bash
# Security remediation for martin-B650M-K — see SECURITY_AUDIT_2026-11-04.md
# Run:  sudo bash ~/harden.sh            (no reboot)
#       sudo bash ~/harden.sh --reboot   (apt upgrade + reboot at the end)
set -euo pipefail
export LC_ALL=C
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
TS=$(date +%Y%m%d%H%M%S)
STUDENTS=(student5 student6 student3 student4 student1)
IDLE_LOCK=(student5 student6 student4)   # 5+ months idle / never logged in
NGROK_URL="https://headscale-tunnel.example"

step(){ echo; echo "===== $*"; }

# student1 data folder / ~/data link (idempotent)
[ -f /home/martin/finish-student1.sh ] && { bash /home/martin/finish-student1.sh || echo "!!! finish-student1.sh failed — continuing"; }

# ---------------------------------------------------------------- M1, L1
step "M1: remove sudo from student6"
gpasswd -d student6 sudo 2>/dev/null || echo "(not in sudo)"
step "L1: lock idle accounts (reverse: usermod -U -e '' <user>)"
for u in "${IDLE_LOCK[@]}"; do usermod -L -e 1 "$u" && echo "locked $u"; done

# ---------------------------------------------------------------- students group
step "students group"
getent group students >/dev/null || groupadd students
for u in "${STUDENTS[@]}"; do usermod -aG students "$u"; done
getent group students

# ---------------------------------------------------------------- H3 + shell pivot: egress firewall
step "H3: student egress firewall (blocks LAN / tailnet / docker nets / local admin ports)"
cat > /usr/local/sbin/student-egress.sh <<'FW'
#!/usr/bin/env bash
# Students may reach the internet (pip, HF) and their own localhost ports (Jupyter, VS Code),
# but NOT: LAN, tailnet, docker networks, or local admin services.
set -e
ADMIN_PORTS=1080,4040,5000,5432,8125,9080,9091,9621,11434,11435,19999
for IPT in iptables ip6tables; do
  $IPT -N STUDENT_EGRESS 2>/dev/null || $IPT -F STUDENT_EGRESS
  $IPT -C OUTPUT -m owner --gid-owner students --suppl-groups -j STUDENT_EGRESS 2>/dev/null \
    || $IPT -I OUTPUT 1 -m owner --gid-owner students --suppl-groups -j STUDENT_EGRESS
  # replies of their own inbound SSH sessions etc.
  $IPT -A STUDENT_EGRESS -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
  $IPT -A STUDENT_EGRESS -o lo -p tcp -m multiport --dports $ADMIN_PORTS -j REJECT
  $IPT -A STUDENT_EGRESS -o lo -j RETURN
done
for NET in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 169.254.0.0/16; do
  iptables -A STUDENT_EGRESS -d $NET -j REJECT
done
for NET in fd7a:115c:a1e0::/48 fc00::/7 fe80::/10; do
  ip6tables -A STUDENT_EGRESS -d $NET -j REJECT
done
iptables -A STUDENT_EGRESS -j RETURN; ip6tables -A STUDENT_EGRESS -j RETURN
FW
chmod 755 /usr/local/sbin/student-egress.sh
cat > /etc/systemd/system/student-egress.service <<'UNIT'
[Unit]
Description=Egress firewall for student accounts
After=network-online.target ufw.service docker.service tailscaled.service
Wants=network-online.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/student-egress.sh
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now student-egress.service
systemctl restart student-egress.service
iptables -S STUDENT_EGRESS

step "H3: sshd — students may forward only to this machine's localhost"
SSHD=/etc/ssh/sshd_config.d/99-user-manager-hardening.conf
if ! grep -q "Match Group students" "$SSHD"; then
  cp -a "$SSHD" "/root/$(basename $SSHD).bak.$TS"
  cat >> "$SSHD" <<'CONF'

Match Group students
    AllowTcpForwarding local
    PermitOpen localhost:* 127.0.0.1:*
    AllowStreamLocalForwarding no
    X11Forwarding no
    PermitTunnel no
    GatewayPorts no
CONF
fi
sshd -t && systemctl reload ssh
# clean stray backup out of sshd_config.d
mv /etc/ssh/sshd_config.d/*.bak.* /root/ 2>/dev/null || true
sshd -T -C user=student1,host=x,addr=100.64.0.9 | grep -E "^(allowtcpforwarding|permitopen|x11forwarding)" || true

# ---------------------------------------------------------------- M2
step "M2: narrow martin NOPASSWD sudo (drop install/mv = root-equivalent)"
SUD=/etc/sudoers.d/oah-agent
cp -a "$SUD" "/root/oah-agent.bak.$TS"
TMP=$(mktemp)
echo "martin ALL=(ALL) NOPASSWD: /usr/local/bin/ollama" > "$TMP"
visudo -cf "$TMP" && install -m 440 -o root -g root "$TMP" "$SUD"; rm -f "$TMP"
cat "$SUD"

# ---------------------------------------------------------------- M3
step "M3: ollama — free VRAM after each request, block LAN access"
install -d /etc/systemd/system/ollama.service.d
cat > /etc/systemd/system/ollama.service.d/10-keepalive.conf <<'CONF'
[Service]
Environment="OLLAMA_KEEP_ALIVE=0"
CONF
systemctl daemon-reload && systemctl restart ollama
ufw deny in on enp6s0 to any port 11434 proto tcp comment 'ollama: no LAN' || true
ufw status numbered | head -30 || true

# ---------------------------------------------------------------- H2 + reboot safety
step "H2: ngrok as a systemd service (agent API disabled via web_addr:false in martin's ngrok.yml)"
cat > /etc/systemd/system/ngrok-headscale.service <<UNIT
[Unit]
Description=ngrok tunnel for Headscale control server
After=network-online.target docker.service
Wants=network-online.target
[Service]
User=martin
ExecStart=/usr/local/bin/ngrok http --url ${NGROK_URL} 9080 --log stdout --log-level warn
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
pkill -u martin -x ngrok || true
sleep 2
systemctl enable --now ngrok-headscale.service
sleep 6
systemctl is-active ngrok-headscale.service
CODE=$(curl -s -m10 -o /dev/null -w "%{http_code}" "${NGROK_URL}/health" || true)
echo "headscale via ngrok: $CODE"
if [ "$CODE" != 200 ]; then
  echo "!!! ngrok service not serving headscale — falling back to the old manual mode"
  systemctl disable --now ngrok-headscale.service || true
  sudo -u martin nohup /usr/local/bin/ngrok http 9080 >/dev/null 2>&1 &
  sleep 6; curl -s -m10 -o /dev/null -w "fallback headscale via ngrok: %{http_code}\n" "${NGROK_URL}/health" || true
fi
curl -s -m3 -o /dev/null -w "ngrok local API (expect 000): %{http_code}\n" http://127.0.0.1:4040/api/tunnels || true

# ---------------------------------------------------------------- L2
step "L2: misc"
chmod 1777 /tmp/RustDesk 2>/dev/null || true
ls -ld /tmp/RustDesk 2>/dev/null || true

# ---------------------------------------------------------------- verify as student
step "verify (as student1)"
sudo -u student1 -H bash -s <<'T'
t(){ timeout 4 bash -c "</dev/tcp/$1/$2" 2>/dev/null && echo "OPEN    $1:$2" || echo "blocked $1:$2"; }
t 127.0.0.1 5000; t 127.0.0.1 11434; t 127.0.0.1 19999; t 192.168.219.50 2294; t 100.64.0.5 22; t 100.64.0.4 22
curl -s -m8 -o /dev/null -w "internet (pypi): %{http_code}\n" https://pypi.org/simple/
nvidia-smi -L
T

# ---------------------------------------------------------------- M4
step "M4: security updates"
# NVIDIA userspace libs must not be upgraded without a reboot (driver/library mismatch breaks the GPU).
if [ "${1:-}" = "--reboot" ]; then
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get -y upgrade
  echo "rebooting in 10s (Ctrl-C to cancel)"; sleep 10; reboot
else
  echo ">>> skipped. When no GPU jobs are running:  sudo bash ~/harden.sh --reboot"
fi
echo DONE
