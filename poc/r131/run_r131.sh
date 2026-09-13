#!/bin/bash
# r131 secure-8192/small (N=19/T=9/H=10) commitment-scheme DESIGN + RAN anatomy legs.
# Arms (same names as dirs): C4 v0/v1/v2, C5 c5_v0/c5_v1/c5_v2.
# 4c-pinned (r126 protocol: 8c-default hit the host ceiling at the 30.15 GiB class; 4c is the
# RAN-safe lane: C4 17.73 GiB peak r126, Swaps 0). Config self-restores (byte-asserted).
set -uo pipefail
HERE=/home/dev/interfold-research/interfold/poc/r131
INTERFOLD=/home/dev/interfold-research/interfold
export PATH="$HOME/.local/bin:$HOME/.nargo/bin:$PATH"
BB="$HOME/.local/bin/bb"
restore() {
  git -C "$INTERFOLD" checkout -- circuits/lib/src/configs/committee/active.nr circuits/lib/src/configs/default/mod.nr 2>/dev/null || true
}
trap restore EXIT
cd "$INTERFOLD" || { echo "FAIL cd"; exit 1; }
{ echo "= r131 box census $(date -u +%H:%M:%S) ="
  echo "nproc=$(nproc)"; grep -E 'MemTotal|MemAvailable|SwapTotal' /proc/meminfo; cat /proc/loadavg
  git -C "$INTERFOLD" rev-parse HEAD
} > "$HERE/box_census.txt"
COMMITTEE=circuits/lib/src/configs/committee/active.nr
DEFAULTM=circuits/lib/src/configs/default/mod.nr
SHA_C_PRE=$(sha256sum "$COMMITTEE" | cut -d' ' -f1)
SHA_D_PRE=$(sha256sum "$DEFAULTM" | cut -d' ' -f1)
{ echo "$SHA_C_PRE"; echo "$SHA_D_PRE"; } > "$HERE/cfg_pre_sha.txt"
cat > /tmp/r131_flip.py <<'PYEOF'
c='circuits/lib/src/configs/committee/active.nr'; s='circuits/lib/src/configs/default/mod.nr'
a=open(c).read(); b=open(s).read()
a2=a.replace('committee::minimum','committee::small')
b2=b.replace('super::insecure::','super::secure::')
assert a!=a2 and b!=b2, 'flip failed (already flipped or pattern missing)'
open(c,'w').write(a2); open(s,'w').write(b2)
print('config flipped min->small, insecure->secure')
PYEOF
python3 /tmp/r131_flip.py >> "$HERE/flip.log" 2>&1
echo "flip rc=$?" >> "$HERE/flip.log"

leg() { # name dir
  local name=$1 dir=$2
  local JJ
  rm -rf "$dir/target"
  ( cd "$INTERFOLD/$dir" && taskset -c 0-3 /usr/bin/time -v stdbuf -oL -eL nargo compile ) >"$HERE/${name}_run.out" 2>&1
  local rc=$?
  echo "${name} compile rc=${rc}" | tee -a "$HERE/leg_status.log"
  JJ=$(find "$dir/target" -name '*.json' 2>/dev/null | head -1)
  if [ -n "$JJ" ]; then
    "$BB" gates -b "$JJ" -t noir-recursive-no-zk > "$HERE/${name}_gates.json" 2>&1
    echo "${name} gates rc=$? artifact=$(basename "$JJ")" | tee -a "$HERE/leg_status.log"
    cp "$JJ" "$HERE/${name}_artifact.json" 2>/dev/null || true
  else
    echo "${name} NO artifact" | tee -a "$HERE/leg_status.log"
  fi
}
echo "== CG 0 $(date -u +%H:%M:%S) ==" | tee -a "$HERE/leg_status.log"
leg c4_v0 poc/r131/v0
leg c4_v1 poc/r131/v1
leg c4_v2 poc/r131/v2
leg c5_v0 poc/r131/c5_v0
leg c5_v1 poc/r131/c5_v1
leg c5_v2 poc/r131/c5_v2
git checkout -- "$COMMITTEE" "$DEFAULTM"
SHA_C_POST=$(sha256sum "$COMMITTEE" | cut -d' ' -f1)
SHA_D_POST=$(sha256sum "$DEFAULTM" | cut -d' ' -f1)
{ echo "cfg pre $SHA_C_PRE $SHA_D_PRE"; echo "cfg post $SHA_C_POST $SHA_D_POST"; \
  if [ "$SHA_C_PRE" = "$SHA_C_POST" ] && [ "$SHA_D_PRE" = "$SHA_D_POST" ]; then echo y=RESTORED; else echo y=CONFIG-MISMATCH; fi; } > "$HERE/cfg_restore.txt"
echo "== CG-0 DONE $(date -u +%H:%M:%S) ==" | tee -a "$HERE/leg_status.log"