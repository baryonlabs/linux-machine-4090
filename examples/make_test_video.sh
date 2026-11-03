#!/usr/bin/env bash
# Make a tiny synthetic video (16 frames, 4 fps, 384x384) for smoke tests.
# Usage: bash make_test_video.sh [out.mp4]
set -euo pipefail
OUT=${1:-$HOME/data/test_video.mp4}
mkdir -p "$(dirname "$OUT")"
ffmpeg -loglevel error -y -f lavfi -i "testsrc=size=384x384:rate=4" -frames:v 16 \
  -pix_fmt yuv420p -c:v libx264 "$OUT"
echo "wrote $OUT"
