#!/usr/bin/env bash
# Run on martin-B650M-K:  sudo bash ~/finish-student1.sh
set -euo pipefail
U=student1

echo "== 1) data folder /mnt/data/users/$U  (+ ~/data symlink)"
install -d -m 700 -o "$U" -g "$U" "/mnt/data/users/$U"
ln -sfn "/mnt/data/users/$U" "/home/$U/data" && chown -h "$U:$U" "/home/$U/data"
ls -ld "/mnt/data/users/$U" "/home/$U/data"

echo "== 3) smoke test as $U"
sudo -u "$U" -H bash -s <<'T'
cd ~
nvidia-smi -L
touch ~/ok ~/data/ok && echo WRITE_OK && rm -f ~/ok ~/data/ok
ls /mnt/data/dev   >/dev/null 2>&1 && echo "LEAK: /mnt/data/dev readable" || echo "BLOCKED: /mnt/data/dev"
ls /mnt/data/users >/dev/null 2>&1 && echo "LEAK: users/ listable"        || echo "BLOCKED: users/ listing"
ls /home/martin    >/dev/null 2>&1 && echo "LEAK: /home/martin readable"   || echo "BLOCKED: /home/martin"
T
SYSTEMD_PAGER= LC_ALL=C chage -l "$U" | grep -i "account expires" || true

echo "== 4) ollama: unload models right after each request (free VRAM)"
install -d /etc/systemd/system/ollama.service.d
cat > /etc/systemd/system/ollama.service.d/10-keepalive.conf <<'CONF'
[Service]
Environment="OLLAMA_KEEP_ALIVE=0"
CONF
systemctl daemon-reload
systemctl restart ollama
systemctl --no-pager show ollama -p Environment
echo DONE
