#!/usr/bin/env bash
# r141 runner 4 (final, clean provenance): re-run the 5 real leg dirs serially,
# direct nargo compile + bb gates (no systemd unit), under ONE locked config
# state whose sha256 is recorded at the start of the sweep and re-asserted
# after each leg. Source tree is unchanged; only mod.nr's two preset `pub use`
# rows are flipped insecure->secure for the sweep, then restored.
#   base      = r137 w6 twin          K=6
#   e_par     = base + 1 parity row   K=6
#   e_par12   = base + 1 parity row   K=12
#   e_range   = base + per-coeff range K=6
#   e_range12 = base + per-coeff range K=12
set -uo pipefail
HERE=/home/dev/interfold-research/interfold/poc/r141_enhanced_shape
INTERFOLD=/home/dev/interfold-research/interfold
export PATH="$HOME/.local/bin:$HOME/.nargo/bin:$PATH"
NARGO="$HOME/.local/bin/nargo"; BB="$HOME/.local/bin/bb"
MOD="$INTERFOLD/circuits/lib/src/configs/default/mod.nr"
MAN="$HERE/RUN4_MANIFEST.txt"; LOG="$HERE/leg4.log"
: > "$MAN"; : > "$LOG"
log(){ printf '%s %s\n' "$(date -u +%H:%M:%SZ)" "$*" | tee -a "$LOG" >/dev/null; echo "[$*]"; }
sha(){ sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }

TOP=$(nproc); FREEGB=$(free -g | awk '/^Mem:/{print $7}')
log "RUN4 START  box=${TOP}c free=${FREEGB}GiB  nargo=$($NARGO --version|head -1) bb=$($BB --version 2>&1|head -1)"

osha_m=$(git -C "$INTERFOLD" show HEAD:circuits/lib/src/configs/default/mod.nr | sha256sum | cut -d' ' -f1)
HSHA=$(git -C "$INTERFOLD" rev-parse HEAD)
log "PROV HEAD=$HSHA origin_main=62cc527fc3 branch.delta 0/83"
log "PROV committed_mod_sha=$osha_m"

# Lock config to SECURE for the whole sweep (idempotent single flip)
if grep -q 'super::insecure::dkg' "$MOD"; then
  cp "$MOD" "$HERE/mod_nr_backup_run4.nr"
  sed -i 's/super::insecure::dkg/super::secure::dkg/; s/super::insecure::threshold/super::secure::threshold/' "$MOD"
fi
SSHA=$(sha "$MOD")
log "PROV SWEEP mod_sha=$SSHA preset=$(grep -m1 'pub use super::secure::dkg\|pub use super::insecure::dkg' $MOD)"

for LEG in base e_par e_par12 e_range e_range12; do
  SUB="$HERE/$LEG"
  [ -f "$SUB/src/main.nr" ] || { log "SKIP $LEG (no main.nr)"; continue; }
  log "=== LEG $LEG START (mod_sha=$SSHA) ==="
  rm -rf "$SUB/target"
  T0=$SECONDS
  ( cd "$SUB" && taskset -c 0-3 "$NARGO" compile 2>&1 ) | tee "$HERE/${LEG}_run_r4.out" | tail -3
  RC=${PIPESTATUS[0]}
  T1=$SECONDS
  ARTIF=$(find "$SUB/target" -name '*.json' 2>/dev/null | grep -v program | head -1)
  log "LEG $LEG compile rc=$RC dt=$((T1-T0))s artifact=[$ARTIF]"
  if [ -n "$ARTIF" ]; then
    ( cd "$SUB" && "$BB" gates -b "$ARTIF" -t noir-recursive-no-zk 2>&1 ) > "$HERE/${LEG}_gates_r4.json" 2>&1
    SZ=$(grep -oE '"circuit_size": [0-9]+' "$HERE/${LEG}_gates_r4.json" | head -1 | grep -oE '[0-9]+')
    AC=$(grep -oE '"acir_opcodes": [0-9]+' "$HERE/${LEG}_gates_r4.json" | head -1 | grep -oE '[0-9]+')
    log "LEG $LEG gates circuit=$SZ acir=$AC"
    echo "$LEG K=$(grep -oE '0\.[0-9]+' "$SUB/src/main.nr" | head -1) circuit=$SZ acir=$AC" >> "$MAN"
  fi
  # re-assert config unchanged mid-sweep
  NOW=$(sha "$MOD")
  [ "$NOW" = "$SSHA" ] || log "WARN mod sha changed during $LEG: $NOW != $SSHA"
done

# Restore committed
git -C "$INTERFOLD" checkout -- "$MOD"
ESHA=$(sha "$MOD")
[ "$ESHA" = "$osha_m" ] && log "RUN4 END OK (mod restored == HEAD $osha_m)" || log "RUN4 END CONFIG-LEAK $ESHA != $osha_m"