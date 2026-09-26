#!/usr/bin/env bash
# r138 — RAN-anchor the r136 in-leaf wall DRAFT.
# Pure verification round: reads r134 leg_h14 (V0/V1/cell/grid) run outputs
# + gates jsons + r137 w6/w12 gates jsons (all prior RAN, on disk), recomputes
# the (a)-drop + in-block + r136 DRAFT self-check, derives the in-leaf
# post-swap wall band, prints RESULT.  NO fresh compile this round
# (the in-tree consumer C4 body is r139 / the owner-re-gate leg).
# See RESULT.txt for the RAN model + the DRAFT-band honesty note.
set -euo pipefail
cd /home/dev/interfold-research/interfold
python3 -u poc/r138/verify_r138.py | tee poc/r138/RAN.out
echo ""
echo "== r138 box census =="
date -u +%Y-%m-%dT%H:%M:%SZ
nproc; grep -E "MemTotal|MemAvailable|SwapTotal" /proc/meminfo | head
echo "HEAD       $(git rev-parse HEAD)"
echo "origin/main $(git rev-parse origin/main)"
git rev-list --left-right --count origin/main...HEAD | awk '{print "ahead/behind "$2"/"$1" (branch vs origin/main)"}'
echo "R138 DONE"