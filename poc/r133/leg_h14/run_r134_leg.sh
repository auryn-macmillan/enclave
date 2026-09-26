#!/usr/bin/env bash
# r134: re-anchor r133's load-bearing numbers on the POST-REBASE small shape.
# Upstream 51fa7415 changed configs/committee/small: H 10 -> 14 (N=19/T=9 same).
# Re-run at 4c-pinned with self-flip + byte-restore (r126/r131/r132 protocol).
set -uo pipefail
HERE=/home/dev/interfold-research/interfold/poc/r133/leg_h14
INTERFOLD=/home/dev/interfold-research/interfold
export PATH="$HOME/.local/bin:$PATH"
BB="$HOME/.local/bin/bb"
COMMITTEE="$INTERFOLD/circuits/lib/src/configs/committee/active.nr"
DEFAULTM="$INTERFOLD/circuits/lib/src/configs/default/mod.nr"
log(){ echo "$(date -u +%H:%M:%S) $*" | tee -a "$HERE/leg.log"; }
git -C "$INTERFOLD" checkout -- "$COMMITTEE" "$DEFAULTM"
{ sha256sum "$COMMITTEE" "$DEFAULTM" | cut -d' ' -f1; } > "$HERE/cfg_pre.txt"
python3 /tmp/r133flip.py > "$HERE/flip.log" 2>&1; echo "flip rc=$?" >> "$HERE/flip.log"
leg(){
  local name=$1 dir=$2
  rm -rf "$dir/target"
  ( cd "$dir" && taskset -c 0-3 /usr/bin/time -v stdbuf -oL -eL ~/.local/bin/nargo compile ) > "$HERE/${name}_run.out" 2>&1
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
leg h14_cell  "$HERE/h14_cell"
leg h14_grid  "$HERE/h14_grid"
leg h14_v0    "$HERE/h14_v0"
leg h14_v1    "$HERE/h14_v1"
git -C "$INTERFOLD" checkout -- "$COMMITTEE" "$DEFAULTM"
{ sha256sum "$COMMITTEE" "$DEFAULTM" | cut -d' ' -f1; } > "$HERE/cfg_post.txt"
diff "$HERE/cfg_pre.txt" "$HERE/cfg_post.txt" > "$HERE/cfg_restore.txt" \
  && echo "CONFIG BYTE-RESTORED (sha equal)" >> "$HERE/cfg_restore.txt" \
  || echo "CONFIG RESTORE MISMATCH" >> "$HERE/cfg_restore.txt"
log "== DONE $(date -u +%Y-%m-%dT%H:%M:%SZ) =="