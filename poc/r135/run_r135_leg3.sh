#!/usr/bin/env bash
# r135 leg-3 (V3): 42-cell (H=14 x L=3) CONSUMER cheap-verify block (r132 p3-class
# x42 at the A production shape). Same self-restore flip protocol as leg-2.
set -uo pipefail
HERE=/home/dev/interfold-research/interfold/poc/r135
INTERFOLD=/home/dev/interfold-research/interfold
export PATH="$HOME/.local/bin:$HOME/.nargo/bin:$PATH"
BB="$HOME/.local/bin/bb"
NARGO="$HOME/.local/bin/nargo"
[ -x "$NARGO" ] || NARGO="$HOME/.nargo/bin/nargo"
COMMITTEE="$INTERFOLD/circuits/lib/src/configs/committee/active.nr"
DEFAULTM="$INTERFOLD/circuits/lib/src/configs/default/mod.nr"
log(){ echo "$(date -u +%H:%M:%S) $*" | tee -a "$HERE/leg3.log"; }
git -C "$INTERFOLD" checkout -- "$COMMITTEE" "$DEFAULTM"
{ sha256sum "$COMMITTEE" "$DEFAULTM" | cut -d' ' -f1; } > "$HERE/cfg3_pre.txt"
python3 /tmp/r135flip2.py > "$HERE/flip3.log" 2>&1; echo "flip rc=$?" >> "$HERE/flip3.log"
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
log "== START V3 $(date -u +%Y-%m-%dT%H:%M:%SZ) =="
leg v3 "$HERE/v3"
git -C "$INTERFOLD" checkout -- "$COMMITTEE" "$DEFAULTM"
{ sha256sum "$COMMITTEE" "$DEFAULTM" | cut -d' ' -f1; } > "$HERE/cfg3_post.txt"
diff "$HERE/cfg3_pre.txt" "$HERE/cfg3_post.txt" > "$HERE/cfg3_restore.txt" \
  && echo "CONFIG BYTE-RESTORED (sha equal)" >> "$HERE/cfg3_restore.txt" \
  || echo "CONFIG RESTORE MISMATCH" >> "$HERE/cfg3_restore.txt"
log "== DONE V3 $(date -u +%Y-%m-%dT%H:%M:%SZ) =="
