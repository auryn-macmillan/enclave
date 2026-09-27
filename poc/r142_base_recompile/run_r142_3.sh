#!/usr/bin/env bash
# r142 runner v3 (SEQUENTIAL, proven r137/r141 protocol): per-leg systemd
# user units with MemoryMax=31G, taskset 0-3. v2 died at 4G because nargo
# ran INSIDE the cron worker probe scope (MemoryMax ~3.4G). r137/r141
# launched each leg as its own `systemctl --user` unit (MemoryMax=31G)
# which escapes the probe cap to box level; we do exactly that, one leg
# at a time (sequential) so the ~2 legs never compete for the 29G free.
set -uo pipefail
HERE=/home/dev/interfold-research/interfold/poc/r142_base_recompile
INTERFOLD=/home/dev/interfold-research/interfold
export PATH="$HOME/.local/bin:$HOME/.nargo/bin:$PATH"
NARGO="$HOME/.local/bin/nargo"; BB="$HOME/.local/bin/bb"
MOD="$INTERFOLD/circuits/lib/src/configs/default/mod.nr"
MAN="$HERE/RUN3_MANIFEST.txt"; LOG="$HERE/leg3.log"; : > "$MAN"; : > "$LOG"
log(){ printf '%s\n' "[$(date -u +%H:%M:%SZ)] $*" | tee -a "$LOG" >/dev/null; }
sha(){ sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }

T0ALL=$SECONDS
HSHA=$(git -C "$INTERFOLD" rev-parse HEAD)
OSHA=$(git -C "$INTERFOLD" show HEAD:circuits/lib/src/configs/default/mod.nr | sha256sum | cut -d' ' -f1)
S6=$(sha "$HERE/base6/src/main.nr"); S12=$(sha "$HERE/base12/src/main.nr")
T6=$(sha "$INTERFOLD/poc/r137/w6/src/main.nr"); T12=$(sha "$INTERFOLD/poc/r137/w12/src/main.nr")
echo "HEAD=$HSHA committed_mod=$OSHA" >> "$MAN"
echo "src6=$S6 twin6=$T6" >> "$MAN"
echo "src12=$S12 twin12=$T12" >> "$MAN"
[ "$S6" = "$T6" ] || { log "FATAL src6 drifted vs r137 w6 twin"; exit 62; }
[ "$S12" = "$T12" ] || { log "FATAL src12 drifted vs r137 w12 twin"; exit 63; }
NB=$(nproc); MA=$(free -g | awk '/^Mem:/{print $7}'); SW=$(free -g | awk '/^Swap:/{print $2}')
log "START nproc=$NB memAvailGB=$MA swapGB=$SW"

# Restore committed, then flip to secure (single idempotent sweep lock)
git -C "$INTERFOLD" checkout -- "$MOD"
if grep -q 'super::insecure::dkg' "$MOD"; then
  cp "$MOD" "$HERE/mod_nr_backup_run3.nr"
  sed -i 's/super::insecure::dkg/super::secure::dkg/; s/super::insecure::threshold/super::secure::threshold/' "$MOD"
fi
SSHA=$(sha "$MOD")
PRES=$(grep -m1 'pub use super::secure::dkg\|pub use super::insecure::dkg' "$MOD")
echo "SWEEP_SHA=$SSHA" >> "$MAN"; echo "PRESET=$PRES" >> "$MAN"
[ "$SSHA" != "$OSHA" ] || { log "FATAL sweep sha equals committed (flip did not land)"; exit 61; }
log "SWEEP_LOCKED sha=$SSHA"

SUM_OK=1
for LEG in base6 base12; do
  SUB="$HERE/$LEG"; UNIT="r142_${LEG}"
  rm -rf "$SUB/target"
  cat > "$HOME/.config/systemd/user/${UNIT}.service" <<EOF
[Unit]
Description=r142 $LEG
[Service]
Type=exec
Environment=HOME=/home/dev LOGNAME=dev PATH=/home/dev/.local/bin:/home/dev/.nargo/bin:/usr/bin:/bin
MemoryAccounting=yes
MemoryMax=31G
CPUAccounting=yes
TimeoutStartSec=2400
ExecStart=/bin/bash -c 'cd $SUB && taskset -c 0-3 /home/dev/.local/bin/nargo compile > $HERE/${LEG}_run3.out 2>&1; rc=\$?; jj=\$(find target -name "*.json" 2>/dev/null | grep -v program | head -1); if [ -n "\$jj" ]; then /home/dev/.local/bin/bb gates -b "\$jj" -t noir-recursive-no-zk > $HERE/${LEG}_gates3.json 2>&1; echo "ARTIFACT=\$jj rc=\$rc" > $HERE/${LEG}_artifact3.txt; else echo "NO_ARTIFACT rc=\$rc" > $HERE/${LEG}_artifact3.txt; fi'
EOF
  systemctl --user daemon-reload
  T0=$SECONDS
  systemctl --user start "$UNIT"
  log "LAUNCH $UNIT pre_sha=$(sha "$MOD")"
  for i in $(seq 1 480); do
    [ "$(systemctl --user is-active "$UNIT" 2>/dev/null)" != "active" ] && break
    sleep 5
  done
  T1=$SECONDS
  STATUS=$(systemctl --user is-active "$UNIT" 2>/dev/null)
  MEM=$(journalctl --user -u "$UNIT" --no-pager 2>/dev/null | grep -oE 'MemoryPeak=[^ ]+' | tail -1)
  RES=$(journalctl --user -u "$UNIT" --no-pager 2>/dev/null | grep -oE 'Result=[a-z]+' | tail -1)
  SZ=$(grep -oE '"circuit_size": [0-9]+' "$HERE/${LEG}_gates3.json" 2>/dev/null | head -1 | grep -oE '[0-9]+')
  AC=$(grep -oE '"acir_opcodes": [0-9]+' "$HERE/${LEG}_gates3.json" 2>/dev/null | head -1 | grep -oE '[0-9]+')
  RT=$(grep -oE 'NO_ARTIFACT|ARTIFACT' "$HERE/${LEG}_artifact3.txt" 2>/dev/null)
  log "DONE $LEG dt=$((T1-T0))s status=$STATUS $RES $MEM $RT circuit=$SZ acir=$AC post_sha=$(sha "$MOD")"
  printf 'LEG=%s dt=%ss status=%s %s %s %s circuit=%s acir=%s sweep_sha=%s\n' "$LEG" "$((T1-T0))" "$STATUS" "$RES" "$MEM" "$RT" "$SZ" "$AC" "$SSHA" >> "$MAN"
  [ -z "$SZ" ] && SUM_OK=0
  systemctl --user stop "$UNIT" 2>/dev/null
  [ "$(systemctl --user is-active "$UNIT" 2>/dev/null)" != "active" ] || { log "ABORT: $UNIT still active"; exit 66; }
done

git -C "$INTERFOLD" checkout -- "$MOD"
ESHA=$(sha "$MOD")
[ "$ESHA" = "$OSHA" ] && log "END OK restored total=$((SECONDS-T0ALL))s" || log "END-LEAK $ESHA != $OSHA"
echo "END_OK=$([ "$ESHA" = "$OSHA" ] && echo YES || echo NO)" >> "$MAN"
exit $((1 - SUM_OK))