#!/usr/bin/env bash
# r135 leg-2 (V2/V2B): FIXED 42-cell (H=14 x L=3) producer-attempt blocks.
# Leg-1 (bpa/bpb) defect: imported L from configs::default::dkg (L=2, the DKG
# QIS count) instead of the threshold L=3 -> 28-cell blocks. V2 sources fix
# the import (configs::secure::threshold::L); everything else carries.
# Taskset 4c up + down-ranging + reused SHA assertion chain: r126/r133/r134.
set -uo pipefail
HERE=/home/dev/interfold-research/interfold/poc/r135
INTERFOLD=/home/dev/interfold-research/interfold
export PATH="$HOME/.local/bin:$HOME/.nargo/bin:$PATH"
BB="$HOME/.local/bin/bb"
NARGO="$HOME/.local/bin/nargo"
[ -x "$NARGO" ] || NARGO="$HOME/.nargo/bin/nargo"
COMMITTEE="$INTERFOLD/circuits/lib/src/configs/committee/active.nr"
DEFAULTM="$INTERFOLD/circuits/lib/src/configs/default/mod.nr"
log(){ echo "$(date -u +%H:%M:%S) $*" | tee -a "$HERE/leg2.log"; }
git -C "$INTERFOLD" checkout -- "$COMMITTEE" "$DEFAULTM"
{ sha256sum "$COMMITTEE" "$DEFAULTM" | cut -d' ' -f1; } > "$HERE/cfg2_pre.txt"
cat > /tmp/r135flip2.py <<'PYEOF'
c="/home/dev/interfold-research/interfold/circuits/lib/src/configs/committee/active.nr"
s="/home/dev/interfold-research/interfold/circuits/lib/src/configs/default/mod.nr"
a=open(c).read(); b=open(s).read()
a2=a.replace('committee::minimum','committee::small')
b2=b.replace('super::insecure::','super::secure::')
assert a!=a2 and b!=b2, 'flip failed (already flipped or pattern missing)'
open(c,'w').write(a2); open(s,'w').write(b2)
print('config flipped min->small, insecure->secure')
PYEOF
python3 /tmp/r135flip2.py > "$HERE/flip2.log" 2>&1; echo "flip rc=$?" >> "$HERE/flip2.log"
leg(){
  local name=$1 dir=$2
  rm -rf "$dir/target"
  ( cd "$dir" && taskset -c 0-3 /usr/bin/time -v stdbuf -oL -eL "$NARGO" compile ) > "$HERE/${name}_run.out" 2>&1
  local rc=$?
  local JJ; JJ=$(find "$dir/target" -name '*.json' 2>/dev/null | grep -v program | head -1)
  log "$name compile rc=$rc"
  if [ -n "$JJ" ]; then
    "$BB" gates -b "$JJ" -t noir-recursive-no-zk > "$HERE/${name}_gates.json" 2>&1
    log "$name gates rc=$? $(head -c 120 "$HERE/${name}_gates.json" | tr -d '\n')"
    cp "$JJ" "$HERE/${name}_artifact.json" 2>/dev/null
  else
    log "$name NO artifact"
  fi
}
log "== START V2 $(date -u +%Y-%m-%dT%H:%M:%SZ) =="
{ echo "== r135 v2 box census $(date -u +%Y-%m-%dT%H:%M:%SZ) =="
  echo "nproc=$(nproc)"
  grep -E 'MemTotal|MemAvailable|SwapTotal' /proc/meminfo
  cat /proc/loadavg
} > "$HERE/box2_census.txt"
leg v2  "$HERE/v2"
leg v2b "$HERE/v2b"
git -C "$INTERFOLD" checkout -- "$COMMITTEE" "$DEFAULTM"
{ sha256sum "$COMMITTEE" "$DEFAULTM" | cut -d' ' -f1; } > "$HERE/cfg2_post.txt"
diff "$HERE/cfg2_pre.txt" "$HERE/cfg2_post.txt" > "$HERE/cfg2_restore.txt" \
  && echo "CONFIG BYTE-RESTORED (sha equal)" >> "$HERE/cfg2_restore.txt" \
  || echo "CONFIG RESTORE MISMATCH" >> "$HERE/cfg2_restore.txt"
log "== DONE V2 $(date -u +%Y-%m-%dT%H:%M:%SZ) =="