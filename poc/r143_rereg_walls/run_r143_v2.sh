#!/usr/bin/env bash
# r143 runner v2 - PER-LEG SYSTEMD USER UNITS (MemoryMax=31G) per the
# r137/r142 protocol: the terminal-worker cgroup is ~4 GiB and r142/v1 of
# this round both in-place-OOM'd there. Each leg = its own unit; T0/T1
# nanosecond wall captured INSIDE the unit script around the scoped
# `taskset -c 0-3 nargo compile`; bb gates inside the same unit. Config
# flip (insecure->secure, DKG preset only) locked for the whole sweep,
# sha256 recorded, restored + sha-asserted at end.
# Legs: e_par12 K=12, e_par24 K=24, e_par42 K=42 — e_par shape = r141
# base cell + ONE Reed-Solomon parity row. e_par12 is a byte-identical
# twin of r141 e_par12; e_par24/e_par42 are K-size seds off it. All THREE
# walls RAN-fresh this round because r141's own per-leg wall logs were
# not preserved (0-byte *_run.out; RUN6 leg6.log timestamps ~1s apart =
# unreliable). A fully RAN 3-pt slope + the K=42 DIRECT point closes the
# r139 45.8s extrapolation AND the r141 wall-quality gap in one sweep.
set -uo pipefail
HERE=/home/dev/interfold-research/interfold/poc/r143_rereg_walls
INTERFOLD=/home/dev/interfold-research/interfold
UNITDIR="$HOME/.config/systemd/user"
NARGO="$HOME/.local/bin/nargo"; BB="$HOME/.local/bin/bb"
MOD="$INTERFOLD/circuits/lib/src/configs/default/mod.nr"
COM="$INTERFOLD/circuits/lib/src/configs/committee/active.nr"
MAN="$HERE/manifest.txt"; LOG="$HERE/leg.log"
: > "$MAN"; : > "$LOG"
log(){ printf '%s %s\n' "$(date -u +%H:%M:%SZ)" "$*" | tee -a "$LOG" >/dev/null; echo "[$*]"; }
sha(){ sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }
HSHA=$(git -C "$INTERFOLD" rev-parse HEAD)
OOSHA=$(git -C "$INTERFOLD" show HEAD:circuits/lib/src/configs/default/mod.nr | sha256sum | cut -d' ' -f1)
echo "HEAD=$HSHA COMMITTED_MOD_SHA=$OOSHA" >> "$MAN"
echo "PROBE_SRC r141_e_par12=$(sha $HERE/../r141_enhanced_shape/e_par12/src/main.nr) local_e_par12=$(sha $HERE/e_par12/src/main.nr) e_par24=$(sha $HERE/e_par24/src/main.nr) e_par42=$(sha $HERE/e_par42/src/main.nr)" >> "$MAN"
{ echo "== r143 box census v2 $(date -u +%Y-%m-%dT%H:%M:%SZ) =="
  echo "nproc=$(nproc)"; grep -E 'MemTotal|MemAvailable|SwapTotal' /proc/meminfo; cat /proc/loadavg
  git -C "$INTERFOLD" rev-parse HEAD; git -C "$INTERFOLD" rev-parse origin/main
} > "$HERE/box_census.txt"
log "START nproc=$(nproc) free=$(free -g | awk '/^Mem:/{print $7}')GiB nargo=$($NARGO --version 2>&1|head -1) bb=$($BB --version 2>&1|head -1)"
if grep -q 'super::insecure::dkg' "$MOD"; then
  cp "$MOD" "$HERE/mod_nr_backup_v2.nr"
  sed -i 's/super::insecure::dkg/super::secure::dkg/; s/super::insecure::threshold/super::secure::threshold/' "$MOD"
fi
SSHA=$(sha "$MOD")
echo "sweep_sha=$SSHA preset_line=$(grep -m1 'pub use super::secure::dkg\|pub use super::insecure::dkg' "$MOD")" >> "$MAN"
log "SWEEP_LOCKED sha=$SSHA"

gen_leg(){
  local LEG="$1"
  cat > "$HERE/legunit_${LEG}.sh" <<EOF
#!/usr/bin/env bash
set -u
cd "$HERE/$LEG" || exit 97
export PATH="$HOME/.local/bin:$PATH"
T0=\$(date +%s.%N)
taskset -c 0-3 "$NARGO" compile > "$HERE/${LEG}_run.out" 2>&1
RC=\$?
T1=\$(date +%s.%N)
{ echo "T0=\$T0"; echo "T1=\$T1"; echo "NARGO_RC=\$RC"; } >> "$HERE/${LEG}_run.out"
jj=\$(find target -name "*.json" 2>/dev/null | grep -v program | head -1)
echo "ARTIFACT=\$jj" > "$HERE/${LEG}_artifact.txt"
[ -n "\$jj" ] && "$BB" gates -b "\$jj" -t noir-recursive-no-zk > "$HERE/${LEG}_gates.json" 2>&1
exit 0
EOF
  chmod +x "$HERE/legunit_${LEG}.sh"
  cat > "$UNITDIR/r143_${LEG}.service" <<EOF
[Unit]
Description=r143 ${LEG} parity-row re-gate wall probe (secure preset)
[Service]
Type=simple
Environment=HOME=/home/dev LOGNAME=dev
MemoryAccounting=yes
MemoryMax=31G
TimeoutStartSec=2400
ExecStart=$HERE/legunit_${LEG}.sh
EOF
}

for LEG in e_par12 e_par24 e_par42; do
  rm -rf "$HERE/$LEG/target" "$HERE/${LEG}_run.out" "$HERE/${LEG}_artifact.txt" "$HERE/${LEG}_gates.json"
  gen_leg "$LEG"
  rm -f "$HERE/${LEG}_after_sha.txt"
  ( grep 'pub use super::' "$MOD" ) | sha256sum | cut -d' ' -f1 > "$HERE/${LEG}_before_sha.txt"
  systemctl --user daemon-reload >/dev/null 2>&1
  systemctl --user reset-failed "r143_${LEG}" 2>/dev/null
  systemctl --user start "r143_${LEG}" 2>&1 | tee -a "$LOG"
  log "launched r143_${LEG}"
  i=0
  while [ "$(systemctl --user is-active "r143_${LEG}" 2>/dev/null)" = "active" ] && [ $i -lt 240 ]; do sleep 10; i=$((i+1)); done
  log "${LEG} ended=$(systemctl --user is-active "r143_${LEG}" 2>/dev/null)"
  journalctl --user -u "r143_${LEG}" --no-pager 2>/dev/null | grep -E 'MemoryPeak|Result=' | tail -4 >> "$LOG"
  grep 'pub use super::' "$MOD" | sha256sum | cut -d' ' -f1 > "$HERE/${LEG}_after_sha.txt"
done

git -C "$INTERFOLD" checkout -- "$MOD" "$COM"
ESHA=$(sha "$MOD")
if [ "$ESHA" = "$OOSHA" ]; then echo "CONFIG RESTORED == committed $OOSHA" >> "$MAN"; log "END OK (mod restored byte-exact)"; else echo "CONFIG RESTORE MISMATCH post=$ESHA expected=$OOSHA" >> "$MAN"; log "CONFIG-LEAK $ESHA != $OOSHA -- RESTORE-NEEDED"; fi
log "== $(date -u +%Y-%m-%dT%H:%M:%SZ) =="
exit 0