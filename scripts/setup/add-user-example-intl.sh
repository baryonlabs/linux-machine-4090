#!/usr/bin/env bash
# Add SSH user for Student Two (VLA/VLM research)
# Run on martin-B650M-K:  sudo bash add-user-student2.sh
set -euo pipefail

NEW_USER="student2"
FULL_NAME="Student Two"
EXP_DATE="2027-01-04"

# 1) Account: no password (key-only), bash, GPU access via video/render/students groups. No sudo.
if ! id "$NEW_USER" &>/dev/null; then
  adduser --disabled-password --gecos "$FULL_NAME" --shell /bin/bash "$NEW_USER"
  echo "Created Linux user $NEW_USER"
else
  echo "User $NEW_USER already exists"
fi

usermod -aG video,render,users,students "$NEW_USER"
usermod -e "$EXP_DATE" "$NEW_USER"
chmod 750 "/home/$NEW_USER"

# 2) Data directory (/mnt/data/users/student2)
DATA_DIR="/mnt/data/users/$NEW_USER"
if [ -d "/mnt/data/users" ]; then
  mkdir -p "$DATA_DIR"
  chown -R "$NEW_USER:$NEW_USER" "$DATA_DIR"
  chmod 700 "$DATA_DIR"
  su - "$NEW_USER" -c "ln -sfn '$DATA_DIR' ~/data" || true
  echo "Prepared data directory $DATA_DIR"
fi

# 3) .ssh directory setup (ready for public key)
install -d -m 700 -o "$NEW_USER" -g "$NEW_USER" "/home/$NEW_USER/.ssh"
AK="/home/$NEW_USER/.ssh/authorized_keys"
touch "$AK"
chown "$NEW_USER:$NEW_USER" "$AK"
chmod 600 "$AK"

# 4) sshd AllowUsers (backup first), validate, reload
for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do
  [ -f "$f" ] || continue
  if grep -qE '^\s*AllowUsers' "$f" && ! grep -qE "^\s*AllowUsers.*\b$NEW_USER\b" "$f"; then
    cp -a "$f" "$f.bak.$(date +%Y%m%d%H%M%S)"
    sed -i -E "s/^(\s*AllowUsers.*)$/\1 $NEW_USER/" "$f"
    echo "Updated AllowUsers in $f"
  fi
done
sshd -t
systemctl reload ssh 2>/dev/null || systemctl reload sshd

# 5) Verify
id "$NEW_USER"
ls -la "/home/$NEW_USER/.ssh"
echo "=== User $NEW_USER onboarded successfully ==="
