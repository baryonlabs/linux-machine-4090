#!/usr/bin/env bash
# Add SSH user for Student One (video multi-target captioning, LoRA on 8B models)
# Run on martin-B650M-K:  sudo bash add-user-student1.sh
set -euo pipefail

NEW_USER="student1"
PUBKEY='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFFvPqZ6z5VpwDrj62nipTVf9bi4eGn495pOtMSAUa6k student1@macbook-ppid'

# 1) Account: no password (key-only), bash, GPU access via video/render groups (same as student5). No sudo.
if ! id "$NEW_USER" &>/dev/null; then
  adduser --disabled-password --gecos "Student One" --shell /bin/bash "$NEW_USER"
fi
usermod -aG video,render,users "$NEW_USER"
usermod -e 2027-01-04 "$NEW_USER"   # 2-month access; extend with: sudo usermod -e YYYY-MM-DD student1
chmod 750 "/home/$NEW_USER"

# 2) authorized_keys
install -d -m 700 -o "$NEW_USER" -g "$NEW_USER" "/home/$NEW_USER/.ssh"
AK="/home/$NEW_USER/.ssh/authorized_keys"
grep -qxF "$PUBKEY" "$AK" 2>/dev/null || echo "$PUBKEY" >> "$AK"
chown "$NEW_USER:$NEW_USER" "$AK"; chmod 600 "$AK"

# 3) sshd AllowUsers (backup first), validate, reload
for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do
  [ -f "$f" ] || continue
  if grep -qE '^\s*AllowUsers' "$f" && ! grep -qE "^\s*AllowUsers.*\b$NEW_USER\b" "$f"; then
    cp -a "$f" "$f.bak.$(date +%Y%m%d%H%M%S)"
    sed -i -E "s/^(\s*AllowUsers.*)$/\1 $NEW_USER/" "$f"
    echo "updated AllowUsers in $f"
  fi
done
sshd -t
systemctl reload ssh 2>/dev/null || systemctl reload sshd

# 4) Verify
id "$NEW_USER"
ls -la "/home/$NEW_USER/.ssh"
grep -hE '^\s*AllowUsers' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* 2>/dev/null
echo "OK: ssh -p 2322 $NEW_USER@<host>"
