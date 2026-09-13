#!/usr/bin/env bash
# r132: (a)-block FINE SPLIT — production C4 verify_commitments per-cell body decomposed.
#   p0 = full per-cell production body (single (party,modulus) cell) — the per-cell base
#   p1 = FLOOR (pin only)
#   p2 = REVERSE pass only
#   p3 = ALIGN+CARRY pack loop (pack::<N,BIT>) on raw coeffs
#   p4 = REVERSE+ALIGN+CARRY (flatten payload), NO SAFE sponge
# Deltas: converging-shape (p0-p4)=SHA-sponge cost; (p4-p3)=reverse cost; (p3-p1)=bitset bit-cost class;
# (p2-p1)=the pure reverse-per-cell.
# Cross-check: p0 gate x 30 cells vs r131 V0-V1 anchor 2,158,861 (itter-scale dump eps <acceptable, labelled).
# Protocol per r126/r131: 4c-pinned, config self-flip + byte-restore (sha-asserted), bb gates plain.
set -uo pipefail
HERE=/home/dev/interfold-research/interfold/poc/r132
INTERFOLD=/home/dev/interfold-research/interfold
export PATH="$HOME/.local/bin:$HOME/.nargo/bin:$PATH"
BB="$HOME/.local/bin/bb"
COMMITTEE=circuits/lib/src/configs/committee/active.nr
DEFAULTM=circuits/lib/src/configs/default/mod.nr
git -C "$INTERFOLD" checkout -- "$COMMITTEE" "$DEFAULTM" 2>/dev/null || true
SHA_C_PRE=$(sha256sum "$INTERFOLD/$COMMITTEE" | cut -d' ' -f1)
SHA_D_PRE=$(sha256sum "$INTERFOLD/$DEFAULTM" | cut -d' ' -f1)
{ echo "$SHA_C_PRE"; echo "$SHA_D_PRE"; } > "$HERE/cfg_pre_sha.txt"
{ echo "= r132 box census $(date -u +%Y-%m-%dT%H:%M:%SZ) ="
  echo "nproc=$(nproc)"
  grep -E 'MemTotal|MemAvailable|SwapTotal' /proc/meminfo
  cat /proc/loadavg
  git -C "$INTERFOLD" rev-parse HEAD
} > "$HERE/box_census.txt"
cat > /tmp/r132_flip.py <<'PYEOF'
c='circuits/lib/src/configs/committee/active.nr'; s='circuits/lib/src/configs/default/mod.nr'
a=open(c).read(); b=open(s).read()
a2=a.replace('committee::minimum','committee::small')
b2=b.replace('super::insecure::','super::secure::')
assert a!=a2 and b!=b2, 'flip failed (already flipped or pattern missing)'
open(c,'w').write(a2); open(s,'w').write(b2)
print('config flipped min->small, insecure->secure')
PYEOF
python3 /tmp/r132_flip.py > "$HERE/flip.log" 2>&1
echo "flip rc=$?" >> "$HERE/flip.log"
leg() { # name dir
  local name=$1 dir=$2
  local JJ
  rm -rf "$INTERFOLD/$dir/target"
  ( cd "$INTERFOLD/$dir" && taskset -c 0-3 /usr/bin/time -v stdbuf -oL -eL nargo compile ) > "$HERE/${name}_run.out" 2>&1
  local rc=$?
  echo "${name} compile rc=${rc}" | tee -a "$HERE/leg_status.log"
  JJ=$(find "$INTERFOLD/$dir/target" -name '*.json' 2>/dev/null | head -1)
  if [ -n "$JJ" ]; then
    "$BB" gates -b "$JJ" -t noir-recursive-no-zk > "$HERE/${name}_gates.json" 2>&1
    echo "${name} gates rc=$? artifact=$(basename "$JJ")" | tee -a "$HERE/leg_status.log"
    cp "$JJ" "$HERE/${name}_artifact.json" 2>/dev/null || true
  else
    echo "${name} NO artifact" | tee -a "$HERE/leg_status.log"
  fi
}
echo "== START $(date -u +%Y-%m-%dT%H:%M:%SZ) ==" | tee -a "$HERE/leg_status.log"
for n in p1 p2 p3 p4 p0; do leg "$n" "poc/r132/$n"; done
git -C "$INTERFOLD" checkout -- "$COMMITTEE" "$DEFAULTM"
SHA_C_POST=$(sha256sum "$INTERFOLD/$COMMITTEE" | cut -d' ' -f1)
SHA_D_POST=$(sha256sum "$INTERFOLD/$DEFAULTM" | cut -d' ' -f1)
{ echo "$SHA_C_POST"; echo "$SHA_D_POST"; } > "$HERE/cfg_post_sha.txt"
diff "$HERE/cfg_pre_sha.txt" "$HERE/cfg_post_sha.txt" > "$HERE/cfg_restore.txt" 2>&1 \
  && echo "CONFIG BYTE-RESTORED (sha equal)" >> "$HERE/cfg_restore.txt" \
  || echo "CONFIG RESTORE MISMATCH" >> "$HERE/cfg_restore.txt"
echo "== DONE $(date -u +%Y-%m-%dT%H:%M:%SZ) ==" | tee -a "$HERE/leg_status.log"