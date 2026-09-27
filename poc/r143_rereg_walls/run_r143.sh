#!/usr/bin/env bash
# r143 runner: RAN wall for the r141 option-(a) parity-row membership
# family (e_par shape) at cell counts 12 / 24 / 42 — the missing WALL
# quality of the r141 parity line. Protocol mirrors r141 run_r141_4.sh:
# ONE locked secure-preset config flip (insecure->secure), recorded sweep
# sha, per-leg taskset 0-3 nargo compile with T0/T1 nanosecond wall,
# bb gates capture, config restored byte-exact and sha-asserted at end.
# e_par24 / e_par42 here are byte-derivatives of r141 e_par12 (K size
# only; md5 of the r141 twin recorded in the manifest).
set -uo pipefail
HERE=/home/dev/interfold-research/interfold/poc/r143_rereg_walls
INTERFOLD=/home/dev/interfold-research/interfold
export PATH="$HOME/.local/bin:$HOME/.nargo/bin:$PATH"
NARGO="$HOME/.local/bin/nargo"; BB="$HOME/.local/bin/bb"
MOD="$INTERFOLD/circuits/lib/src/configs/default/mod.nr"
COM="$INTERFOLD/circuits/lib/src/configs/committee/active.nr"
MAN="$HERE/manifest.txt"; LOG="$HERE/leg.log"
: > "$MAN"; : > "$LOG"
log(){ printf '%s %s\n' "$(date -u +%H:%M:%SZ)" "$*" | tee -a "$LOG" >/dev/null; echo "[$*]"; }
sha(){ sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }
H=$(git -C "$INTERFOLD" rev-parse HEAD)
OOSHA=$(git -C "$INTERFOLD" show HEAD:circuits/lib/src/configs/default/mod.nr | sha256sum | cut -d' ' -f1)
echo "HEAD=$H COMMITTED_MOD_SHA=$OOSHA" >> "$MAN"
echo "PROBE_SRC e_par12=$(sha $HERE/../r141_enhanced_shape/e_par12/src/main.nr) e_par24=$(sha $HERE/e_par24/src/main.nr) e_par42=$(sha $HERE/e_par42/src/main.nr)" >> "$MAN"
{ echo "== r143 box census $(date -u +%Y-%m-%dT%H:%M:%SZ) =="
  echo "nproc=$(nproc)"; grep -E 'MemTotal|MemAvailable|SwapTotal' /proc/meminfo; cat /proc/loadavg
  git -C "$INTERFOLD" rev-parse HEAD; git -C "$INTERFOLD" rev-parse origin/main
} > "$HERE/box_census.txt"
log "START nargo=$($NARGO --version 2>&1 | head -1) bb=$($BB --version 2>&1 | head -1)"
# lock config to secure (idempotent single flip), record sweep sha
if grep -q 'super::insecure::dkg' "$MOD"; then
  cp "$MOD" "$HERE/mod_nr_backup.nr"
  sed -i 's/super::insecure::dkg/super::secure::dkg/; s/super::insecure::threshold/super::secure::threshold/' "$MOD"
fi
SSHA=$(sha "$MOD")
echo "sweep_sha=$SSHA preset_line=$(grep -m1 'pub use super::secure::dkg\|pub use super::insecure::dkg' "$MOD")" >> "$MAN"
log "SWEEP_LOCKED sha=$SSHA"
for LEG in e_par12 e_par24 e_par42; do
  SUB="$HERE/$LEG"
  [ -f "$SUB/src/main.nr" ] || { log "SKIP $LEG (no main.nr)"; continue; }
  log "=== LEG $LEG START (mod_sha=$SSHA) ==="
  rm -rf "$SUB/target"
  T0=$(date +%s.%N)
  ( cd "$SUB" && taskset -c 0-3 "$NARGO" compile 2>&1 ) | tee "$HERE/${LEG}_run.out" | tail -3
  RC=${PIPESTATUS[0]}
  T1=$(date +%s.%N)
  DT=$(python3 -c "print(round($T1-$T0,3))")
  ARTIF=$(find "$SUB/target" -name '*.json' 2>/dev/null | grep -v program | head -1)
  log "LEG $LEG compile rc=$RC dt=${DT}s T0=$T0 T1=$T1 artifact=[$ARTIF]"
  echo "T0=$T0 T1=$T1 DT=$DT NARGO_RC=$RC" >> "$HERE/${LEG}_run.out"
  if [ -n "$ARTIF" ]; then
    ( cd "$SUB" && "$BB" gates -b "$ARTIF" -t noir-recursive-no-zk 2>&1 ) > "$HERE/${LEG}_gates.json" 2>&1
    SZ=$(grep -oE '"circuit_size": [0-9]+' "$HERE/${LEG}_gates.json" | head -1 | grep -oE '[0-9]+')
    AC=$(grep -oE '"acir_opcodes": [0-9]+' "$HERE/${LEG}_gates.json" | head -1 | grep -oE '[0-9]+')
    log "LEG $LEG gates circuit=$SZ acir=$AC"
    echo "$LEG circuit=$SZ acir=$AC dt=$DT rc=$RC" >> "$MAN"
  else
    echo "$LEG circuit=OOM_or_fail acir=- dt=$DT rc=$RC" >> "$MAN"
  fi
  NOW=$(sha "$MOD")
  [ "$NOW" = "$SSHA" ] || log "WARN mod sha changed during $LEG: $NOW != $SSHA"
done
git -C "$INTERFOLD" checkout -- "$MOD" "$COM" 2>/dev/null
ESHA=$(sha "$MOD")
if [ "$ESHA" = "$OOSHA" ]; then echo "CONFIG RESTORED == committed $OOSHA" >> "$MAN"; log "END OK (mod restored byte-exact)"; else echo "CONFIG RESTORE MISMATCH post=$ESHA expected=$OOSHA" >> "$MAN"; log "CONFIG-LEAK $ESHA != $OOSHA"; fi
log "== $(date -u +%Y-%m-%dT%H:%M:%SZ) =="
exit 0