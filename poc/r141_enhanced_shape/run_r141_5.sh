#!/usr/bin/env bash
# r141 runner 5 (final, fully-manifested): ONE locked config state for the
# whole sweep; each leg's config_sha is captured BEFORE its nargo compile
# and AGAIN after, and the parsable JSON is stored at ${LEG}_gates_r5.json.
# Leg set: base, e_par, e_par12, e_range, e_range12.
set -uo pipefail
HERE=/home/dev/interfold-research/interfold/poc/r141_enhanced_shape
INTERFOLD=/home/dev/interfold-research/interfold
export PATH="$HOME/.local/bin:$HOME/.nargo/bin:$PATH"
NARGO="$HOME/.local/bin/nargo"; BB="$HOME/.local/bin/bb"
MOD="$INTERFOLD/circuits/lib/src/configs/default/mod.nr"
MAN="$HERE/RUN5_MANIFEST.txt"; LOG="$HERE/leg5.log"
: > "$MAN"; : > "$LOG"
log(){ printf '%s\n' "[$(date -u +%H:%M:%SZ)] $*" | tee -a "$LOG" >/dev/null; }
sha(){ sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }

TOP=$(nproc); FREEGB=$(free -g | awk '/^Mem:/{print $7}')
log "RUN5 START ${TOP}c ${FREEGB}GiB"

HSHA=$(git -C "$INTERFOLD" rev-parse HEAD)
OSHA=$(git -C "$INTERFOLD" show HEAD:circuits/lib/src/configs/default/mod.nr | sha256sum | cut -d' ' -f1)
log "HEAD=$HSHA committed_mod=$OSHA"

# Lock to secure, single, idempotent
if grep -q 'super::insecure::dkg' "$MOD"; then
  cp "$MOD" "$HERE/mod_nr_backup_run5.nr"
  sed -i 's/super::insecure::dkg/super::secure::dkg/; s/super::insecure::threshold/super::secure::threshold/' "$MOD"
fi
SSHA=$(sha "$MOD")
PRESET_LINE=$(grep -m1 'pub use super::' "$MOD" | tail -1)
log "SWEEP_LOCKED sha=$SSHA preset_line=$PRESET_LINE"
echo "SWEEP $SSHA $PRESET_LINE" >> "$MAN"

for LEG in base e_par e_par12 e_range e_range12; do
  SUB="$HERE/$LEG"
  [ -f "$SUB/src/main.nr" ] || { log "SKIP $LEG (no main.nr)"; continue; }
  K=$(grep -oE 'Polynomial<N>; [0-9]+' "$SUB/src/main.nr" | head -1 | grep -oE '[0-9]+')
  log "=== LEG $LEG (K=$K) SHA_PRE=$(sha "$MOD") ==="
  rm -rf "$SUB/target"
  T0=$SECONDS
  ( cd "$SUB" && taskset -c 0-3 "$NARGO" compile 2>&1 ) | tee "$HERE/${LEG}_run_r5.out" | tail -2
  RC=$?
  T1=$SECONDS
  log "LEG $LEG rc=$RC dt=$((T1-T0))s SHA_POST=$(sha "$MOD")"
  ARTIF=$(find "$SUB/target" -name '*.json' 2>/dev/null | grep -v 'program\|journal' | head -1)
  if [ -n "$ARTIF" ]; then
    ( cd "$SUB" && "$BB" gates -b "$ARTIF" -t noir-recursive-no-zk 2>&1 ) > "$HERE/${LEG}_gates_r5.json"
    SZ=$(grep -oE '"circuit_size": [0-9]+' "$HERE/${LEG}_gates_r5.json" | head -1 | grep -oE '[0-9]+')
    AC=$(grep -oE '"acir_opcodes": [0-9]+' "$HERE/${LEG}_gates_r5.json" | head -1 | grep -oE '[0-9]+')
    log "LEG $LEG circuit=$SZ acir=$AC"
    printf '%s K=%s circuit=%s acir=%s sha=%s\n' "$LEG" "$K" "$SZ" "$AC" "$SSHA" >> "$MAN"
  else
    log "LEG $LEG NO-ARTIFACT"
    printf '%s K=%s NO-ARTIFACT sha=%s\n' "$LEG" "$K" "$SSHA" >> "$MAN"
  fi
done

git -C "$INTERFOLD" checkout -- "$MOD"
ESHA=$(sha "$MOD")
[ "$ESHA" = "$OSHA" ] && log "RUN5 END OK" || log "RUN5 END-LEAK $ESHA != $OSHA"