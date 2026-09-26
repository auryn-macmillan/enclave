#!/usr/bin/env bash
# r133: PRODUCER-ATTESTATION floor probe (I18/I19 design round 3, owner-signed lever).
#   a0 = single-cell DirectSHA forward arm (C2-orientation twin of r132 p4; CG-0 BIT=58)
#   a1 = single-cell MerkleNode arm (two safe-commitment leaves + ONE node, node OUT pinned)
#   b0 = 30-cell (H=10 x L=3) MerkleNode block at PRODUCTION scale
#   b1 = 30-cell DirectSHA block at PRODUCTION scale (B0 shape twin)
# AB-DELTA (like-for-like, block scale): b1 vs b0 = direct-sha vs Merkle-node binding cost;
# A-DELTA: a0 vs a1 = single-cell per-share direct-sha vs per-cell Merkle node.
# Deltas are NON-additive across arms (shared intermediate wires, r132 lesson) - whole-arm only.
# Calibration: b1 vs r132 p4 x30 label 2,159,430 / r131 (a) block 2,158,861; a0 vs r132 p4 71,981.
# Protocol per r126/r131/r132: 4c-pinned taskset, config self-flip + byte-restore sha-asserted.
set -uo pipefail
HERE=/home/dev/interfold-research/interfold/poc/r133
INTERFOLD=/home/dev/interfold-research/interfold
export PATH="$HOME/.local/bin:$HOME/.nargo/bin:$PATH"
BB="$HOME/.local/bin/bb"
COMMITTEE=circuits/lib/src/configs/committee/active.nr
DEFAULTM=circuits/lib/src/configs/default/mod.nr
git -C "$INTERFOLD" checkout -- "$COMMITTEE" "$DEFAULTM" 2>/dev/null || true
SHA_C_PRE=$(sha256sum "$INTERFOLD/$COMMITTEE" | cut -d' ' -f1)
SHA_D_PRE=$(sha256sum "$INTERFOLD/$DEFAULTM" | cut -d' ' -f1)
{ echo "$SHA_C_PRE"; echo "$SHA_D_PRE"; } > "$HERE/cfg_pre_sha.txt"
{ echo "= r133 box census $(date -u +%Y-%m-%dT%H:%M:%SZ) ="
  echo "nproc=$(nproc)"
  grep -E 'MemTotal|MemAvailable|SwapTotal' /proc/meminfo
  cat /proc/loadavg
  git -C "$INTERFOLD" rev-parse HEAD
} > "$HERE/box_census.txt"
mkdir -p /tmp/r133flip
cat > /tmp/r133flip/flip.py <<'PYEOF'
c="/home/dev/interfold-research/interfold/circuits/lib/src/configs/committee/active.nr"; s="/home/dev/interfold-research/interfold/circuits/lib/src/configs/default/mod.nr"
a=open(c).read(); b=open(s).read()
a2=a.replace('committee::minimum','committee::small')
b2=b.replace('super::insecure::','super::secure::')
assert a!=a2 and b!=b2, 'flip failed (already flipped or pattern missing)'
open(c,'w').write(a2); open(s,'w').write(b2)
print('config flipped min->small, insecure->secure')
PYEOF
python3 /tmp/r133flip/flip.py > "$HERE/flip.log" 2>&1
echo "flip rc=$?" >> "$HERE/flip.log"
leg() { # name dir
  local name=$1 dir=$2
  local JJ
  rm -rf "$INTERFOLD/$dir/target"
  ( cd "$INTERFOLD/$dir" && taskset -c 0-3 /usr/bin/time -v stdbuf -oL -eL nargo compile ) > "$HERE/${name}_run.out" 2>&1
  local rc=$?
  echo "${name} compile rc=${rc} $(date -u +%H:%M:%S)" | tee -a "$HERE/leg_status.log"
  JJ=$(find "$INTERFOLD/$dir/target" -name '*.json' 2>/dev/null | head -1)
  if [ -n "$JJ" ]; then
    "$BB" gates -b "$JJ" -t noir-recursive-no-zk > "$HERE/${name}_gates.json" 2>&1
    echo "${name} gates rc=$? artifact=$(basename "$JJ") $(date -u +%H:%M:%S)" | tee -a "$HERE/leg_status.log"
    cp "$JJ" "$HERE/${name}_artifact.json" 2>/dev/null || true
  else
    echo "${name} NO artifact" | tee -a "$HERE/leg_status.log"
  fi
}
echo "== START $(date -u +%Y-%m-%dT%H:%M:%SZ) ==" | tee -a "$HERE/leg_status.log"
for n in a0 a1 b0 b1; do leg "$n" "poc/r133/$n"; done
git -C "$INTERFOLD" checkout -- "$COMMITTEE" "$DEFAULTM"
SHA_C_POST=$(sha256sum "$INTERFOLD/$COMMITTEE" | cut -d' ' -f1)
SHA_D_POST=$(sha256sum "$INTERFOLD/$DEFAULTM" | cut -d' ' -f1)
{ echo "$SHA_C_POST"; echo "$SHA_D_POST"; } > "$HERE/cfg_post_sha.txt"
diff "$HERE/cfg_pre_sha.txt" "$HERE/cfg_post_sha.txt" > "$HERE/cfg_restore.txt" 2>&1 \
  && echo "CONFIG BYTE-RESTORED (sha equal)" >> "$HERE/cfg_restore.txt" \
  || echo "CONFIG RESTORE MISMATCH" >> "$HERE/cfg_restore.txt"
echo "== DONE $(date -u +%Y-%m-%dT%H:%M:%SZ) ==" | tee -a "$HERE/leg_status.log"