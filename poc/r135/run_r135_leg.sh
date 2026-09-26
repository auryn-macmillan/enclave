#!/usr/bin/env bash
# r135: FULL-SCALE producer-side attestation block at the A production shape
# (H=14, 42 cells, secure-8192/small N=19/T=9, L=3, BIT_MSG=58; post-rebase
# upstream 51fa7415 small config H 10->14 = r134's re-anchor shape).
#   bpa = 42-cell DIRECT-SHA producer block (r133 b1 shape restated at H14;
#         per-cell twin h14_cell 71,981 g; the "producer re-hashes every share"
#         route at production cell count)
#   bpb = 42-cell MERKLE-NODE producer block (r133 a1 shape x42: per-cell the
#         producer builds BOTH leaf commitments + ONE SAFE node, node pinned;
#         per-cell twin isolated a1 = 164,484 g at H10)
# Like-for-like anchor: h14_v0 - h14_v1 = 3,022,405 g (the consumer re-commit
# block this producer route would displace, r134 RAN).
# Protocol per r126/r133/r134: 4c-pinned taskset, config self-flip
# (committee active minimum->small, default insecure->secure) + byte-restore
# sha-asserted. CG-0 field: secure-8192/small.
set -uo pipefail
HERE=/home/dev/interfold-research/interfold/poc/r135
INTERFOLD=/home/dev/interfold-research/interfold
export PATH="$HOME/.local/bin:$HOME/.nargo/bin:$PATH"
BB="$HOME/.local/bin/bb"
NARGO="$HOME/.local/bin/nargo"
[ -x "$NARGO" ] || NARGO="$HOME/.nargo/bin/nargo"
COMMITTEE="$INTERFOLD/circuits/lib/src/configs/committee/active.nr"
DEFAULTM="$INTERFOLD/circuits/lib/src/configs/default/mod.nr"
log(){ echo "$(date -u +%H:%M:%S) $*" | tee -a "$HERE/leg.log"; }
git -C "$INTERFOLD" checkout -- "$COMMITTEE" "$DEFAULTM"
{ sha256sum "$COMMITTEE" "$DEFAULTM" | cut -d' ' -f1; } > "$HERE/cfg_pre.txt"
{ echo "== r135 box census $(date -u +%Y-%m-%dT%H:%M:%SZ) =="
  echo "nproc=$(nproc)"
  grep -E 'MemTotal|MemAvailable|SwapTotal' /proc/meminfo
  cat /proc/loadavg
  git -C "$INTERFOLD" rev-parse HEAD
  git -C "$INTERFOLD" rev-parse origin/main
} > "$HERE/box_census.txt"
cat > /tmp/r135flip.py <<'PYEOF'
c="/home/dev/interfold-research/interfold/circuits/lib/src/configs/committee/active.nr"; s="/home/dev/interfold-research/interfold/circuits/lib/src/configs/default/mod.nr"
a=open(c).read(); b=open(s).read()
a2=a.replace('committee::minimum','committee::small')
b2=b.replace('super::insecure::','super::secure::')
assert a!=a2 and b!=b2, 'flip failed (already flipped or pattern missing)'
open(c,'w').write(a2); open(s,'w').write(b2)
print('config flipped min->small, insecure->secure')
PYEOF
python3 /tmp/r135flip.py > "$HERE/flip.log" 2>&1; echo "flip rc=$?" >> "$HERE/flip.log"
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
log "== START $(date -u +%Y-%m-%dT%H:%M:%SZ) =="
leg bpa "$HERE/bpa"
leg bpb "$HERE/bpb"
git -C "$INTERFOLD" checkout -- "$COMMITTEE" "$DEFAULTM"
{ sha256sum "$COMMITTEE" "$DEFAULTM" | cut -d' ' -f1; } > "$HERE/cfg_post.txt"
diff "$HERE/cfg_pre.txt" "$HERE/cfg_post.txt" > "$HERE/cfg_restore.txt" \
  && echo "CONFIG BYTE-RESTORED (sha equal)" >> "$HERE/cfg_restore.txt" \
  || echo "CONFIG RESTORE MISMATCH" >> "$HERE/cfg_restore.txt"
log "== DONE $(date -u +%Y-%m-%dT%H:%M:%SZ) =="