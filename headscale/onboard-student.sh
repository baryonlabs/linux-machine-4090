#!/usr/bin/env bash
# Run as martin on martin-B650M-K (docker group, no sudo needed).
# Usage: bash onboard-student.sh kimsunghyun
set -euo pipefail
U="${1:?username}"
HS="docker exec headscale headscale"

$HS users list -o json | grep -q "\"name\": *\"$U\"" || $HS users create "$U"
UID_=$($HS users list -o json | python3 -c "import json,sys;print(next(u['id'] for u in json.load(sys.stdin) if u['name']=='$U'))")

# single-use pre-auth key, valid 60 days (registration window).
# Node access itself is cut by a cron job on the access end date (see `crontab -l | grep hs-expire`).
$HS preauthkeys create --user "$UID_" --expiration 1440h
