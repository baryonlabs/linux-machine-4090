#!/usr/bin/env bash
# Headscale VPN Node Inspection & Key Reissue Tool for ops-watch
# Safe execution: Checks registered nodes, expires suspicious nodes, and generates a fresh pre-auth key.
# Usage: bash reissue-student-key.sh [username] [--execute]

set -euo pipefail
U="${1:-student1}"
EXEC="${2:-preview}"
HS="docker exec headscale headscale"

echo "=== Headscale Security Inspection for user: $U ==="

# Check docker availability
if ! command -v docker &>/dev/null; then
    echo "[Simulation Mode] docker not available locally on this machine."
    echo "Proposed Actions on Research Server (martin-B650M-K):"
    echo "1. List existing nodes for $U:  $HS nodes list -o json"
    echo "2. Expire suspicious node:      $HS nodes expire -i <node_id>"
    echo "3. Generate new Pre-Auth Key:  $HS preauthkeys create --user $U --expiration 720h"
    exit 0
fi

# List current nodes for user
echo "1. Checking active nodes for user '$U'..."
NODES=$($HS nodes list -o json 2>/dev/null || echo "[]")
USER_NODES=$(echo "$NODES" | python3 -c "
import sys, json
try:
    nodes = json.load(sys.stdin)
    matching = [n for n in nodes if n.get('user', {}).get('name') == '$U']
    for n in matching:
        print(f\"Node ID: {n.get('id')} | Name: {n.get('given_name')} | IP: {n.get('ip_addresses')} | Online: {n.get('online')} | LastSeen: {n.get('last_seen')}\")
except Exception as e:
    pass
")

if [ -n "$USER_NODES" ]; then
    echo "$USER_NODES"
else
    echo "No registered nodes currently found for $U."
fi

if [ "$EXEC" = "--execute" ]; then
    echo ""
    echo "2. Expiring existing nodes for user '$U'..."
    NODE_IDS=$(echo "$NODES" | python3 -c "
import sys, json
try:
    nodes = json.load(sys.stdin)
    print(' '.join(str(n['id']) for n in nodes if n.get('user', {}).get('name') == '$U'))
except Exception:
    pass
")
    for nid in $NODE_IDS; do
        echo "Expiring node ID $nid..."
        $HS nodes expire -i "$nid" || true
    done

    echo ""
    echo "3. Issuing fresh single-use Pre-Auth Key..."
    $HS users list -o json | grep -q "\"name\": *\"$U\"" || $HS users create "$U"
    UID_=$($HS users list -o json | python3 -c "import json,sys;print(next(u['id'] for u in json.load(sys.stdin) if u['name']=='$U'))")
    NEW_KEY=$($HS preauthkeys create --user "$UID_" --expiration 720h -o json | python3 -c "import json,sys; print(json.load(sys.stdin).get('key', ''))")
    
    echo "============================================================"
    echo "NEW HEADSCALE PRE-AUTH KEY (Single-Use, 30 Days):"
    echo "$NEW_KEY"
    echo "============================================================"
else
    echo ""
    echo "Preview only. Run with '--execute' to expire old nodes and issue new key."
fi
