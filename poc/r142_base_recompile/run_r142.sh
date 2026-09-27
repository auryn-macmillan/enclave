#!/usr/bin/env bash
# r142 runner v2: freshly recompile base K=6 and K=12 (the two INHERITED
# r137 denominators) with FULL stdout captured per leg. The .nr sources
# are byte-identical copies of poc/r137/w6 and poc/r137/w12 (md5 checked
# inside this script before launching). Protocol mirrors r141 run 6:
# one locked secure-preset config sha for the whole sweep, restore to
# committed afterwards.
set -uo pipefail
HERE=/home/dev/interfold-research/interfold/poc/r142_base_recompile
INTERFOLD=/home/dev/interfold-research/interfold
export PATH="$HOME/.local/bin:$HOME/.nargo/bin:$PATH"
NARGO="$HOME/.local/bin/nargo"; BB="$HOME/.local/bin/bb"
MOD="$INTERFOLD/circuits/lib/src/configs/default/mod.nr"
MAN="$HERE/manifest.txt"; LOG="$HERE/leg.log"; : > "$MAN"; : > "$LOG"
log(){ printf '%s\n' "[$(date -u +%H:%M:%SZ)] $*" | tee -a "$LOG" >/dev/null; }
sha(){ sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }

T0ALL=$SECONDS
HSHA=$(git -C "$INTERFOLD" rev-parse HEAD)
OSHA=$(git -C "$INTERFOLD" show HEAD:circuits/lib/src/configs/default/mod.nr | sha256sum | cut -d' ' -f1)
S6=$(sha "$HERE/base6/src/main.nr")
S12=$(sha "$HERE/base12/src/main.nr")
T6=$(sha "$INTERFOLD/poc/r137/w6/src/main.nr")
T12=$(sha "$INTERFOLD/poc/r137/w12/src/main.nr")
echo "HEAD=$HSHA committed_mod=$OSHA" >> "$MAN"
echo "src6=$S6 twin6=$T6" >> "$MAN"
echo "src12=$S12 twin12=$T12" >> "$MAN"
[ "$S6" = "$T6" ] || { log "FATAL src6 drifted vs r137 twin"; exit 62; }
[ "$S12" = "$T12" ] || { log "FATAL src12 drifted vs r137 twin"; exit 63; }

NB=$(nproc); MA=$(free -g | awk '/^Mem:/{print $7}'); SW=$(free -g | awk '/^Swap:/{print $2}')
log "START nproc=$NB mem_available_GiB=$MA swap_GiB=$SW"

if grep -q 'super::insecure::dkg' "$MOD"; then
  cp "$MOD" "$HERE/mod_nr_backup.nr"
  sed -i 's/super::insecure::dkg/super::secure::dkg/; s/super::insecure::threshold/super::secure::threshold/' "$MOD"
fi
SSHA=$(sha "$MOD")
PRES=$(grep -m1 'pub use super::secure::dkg\|pub use super::insecure::dkg' "$MOD")
echo "sweep_sha=$SSHA preset=$PRES" >> "$MAN"
[ "$SSHA" != "$OSHA" ] || { log "FATAL sweep sha equals committed sha (flip did not land)"; exit 61; }
log "SWEEP_LOCKED sha=$SSHA"

for LEG in base6 base12; do
  SUB="$HERE/$LEG"
  rm -rf "$SUB/target"
  T0=$SECONDS
  ( cd "$SUB" && taskset -c 0-3 "$NARGO" compile 2>&1 ) > "$HERE/${LEG}_run.out"
  RC=$?
  T1=$SECONDS
  ARTIF=$(find "$SUB/target" -name '*.json' 2>/dev/null | grep -v 'program\|journal' | head -1)
  SZ=; AC=
  if [ -n "$ARTIF" ]; then
    ( cd "$SUB" && "$BB" gates -b "$ARTIF" -t noir-recursive-no-zk 2>&1 ) > "$HERE/${LEG}_gates.json"
    SZ=$(grep -oE '"circuit_size": [0-9]+' "$HERE/${LEG}_gates.json" | head -1 | grep -oE '[0-9]+')
    AC=$(grep -oE '"acir_opcodes": [0-9]+' "$HERE/${LEG}_gates.json" | head -1 | grep -oE '[0-9]+')
  fi
  NT=$(wc -l < "$HERE/${LEG}_run.out")
  log "LEG $LEG rc=$RC dt=$((T1-T0))s stdout_lines=$NT circuit=$SZ acir=$AC post_sha=$(sha "$MOD")"
  printf 'LEG=%s rc=%s dt=%ss circuit=%s acir=%s sweep_sha=%s\n' "$LEG" "$RC" "$((T1-T0))" "$SZ" "$AC" "$SSHA" >> "$MAN"
done

git -C "$INTERFOLD" checkout -- "$MOD"
ESHA=$(sha "$MOD")
[ "$ESHA" = "$OSHA" ] && log "END OK restored to committed total=$((SECONDS-T0ALL))s" || log "END-LEAK $ESHA != $OSHA"
echo "END_OK=$([ "$ESHA" = "$OSHA" ] && echo YES || echo NO)" >> "$MAN"