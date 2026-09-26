#!/usr/bin/env bash
# r135 leg-4 (V3S) v2: memory-slope probe for the consumer cheap-verify leg
# (leg-3 42-cell v3 OOM at the 28 GiB unit cap). V3S = 6 cells (minimum
# committee H=2 x threshold L=3) — only the DKG preset flips
# (insecure->secure); committee stays minimum. All paths absolute (leg-4 v1
# wrote outputs to $HOME via systemd-relative cwd — recorded as infra defect;
# tree-touched files absent, config already byte-restored in leg-4 v1).
set -uo pipefail
HERE=/home/dev/interfold-research/interfold/poc/r135
INTERFOLD=/home/dev/interfold-research/interfold
export PATH="$HOME/.local/bin:$HOME/.nargo/bin:$PATH"
BB="$HOME/.local/bin/bb"
NARGO="$HOME/.local/bin/nargo"
[ -x "$NARGO" ] || NARGO="$HOME/.nargo/bin/nargo"
DEFAULTM="$INTERFOLD/circuits/lib/src/configs/default/mod.nr"
log(){ echo "$(date -u +%H:%M:%S) $*" | tee -a "$HERE/leg4.log"; }
git -C "$INTERFOLD" checkout -- "$DEFAULTM"
{ sha256sum "$DEFAULTM" | cut -d' ' -f1; } > "$HERE/cfg4_pre.txt"
python3 /tmp/r135flip4.py > /tmp/r135flip4.log 2>&1; echo "flip rc=$?" >> /tmp/r135flip4.log
cp /tmp/r135flip4.log "$HERE/flip4b.log" 2>/dev/null
rm -rf "$HERE/v3s/target"
( cd "$HERE/v3s" && taskset -c 0-3 /usr/bin/time -v stdbuf -oL -eL "$NARGO" compile ) > "$HERE/v3s_run.out" 2>&1
rc=$?
JJ=$(find "$HERE/v3s/target" -name '*.json' 2>/dev/null | grep -v program | head -1)
log "v3s compile rc=$rc"
if [ -n "$JJ" ]; then
  "$BB" gates -b "$JJ" -t noir-recursive-no-zk > "$HERE/v3s_gates.json" 2>&1
  log "v3s gates rc=$? $(head -c 120 "$HERE/v3s_gates.json" | tr -d '\n')"
else
  log "v3s NO artifact"
fi
git -C "$INTERFOLD" checkout -- "$DEFAULTM"
{ sha256sum "$DEFAULTM" | cut -d' ' -f1; } > "$HERE/cfg4_post.txt"
diff "$HERE/cfg4_pre.txt" "$HERE/cfg4_post.txt" > "$HERE/cfg4_restore.txt" \
  && echo "CONFIG BYTE-RESTORED (sha equal)" >> "$HERE/cfg4_restore.txt" \
  || echo "CONFIG RESTORE MISMATCH" >> "$HERE/cfg4_restore.txt"
log "== DONE V3S $(date -u +%Y-%m-%dT%H:%M:%SZ) =="