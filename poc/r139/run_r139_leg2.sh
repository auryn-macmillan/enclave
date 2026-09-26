#!/usr/bin/env bash
# r139 leg 2 - c12 probe only (config already byte-restored to baseline by
# run_r139.sh; this runner re-does the single-leg flip under its own unit,
# with the same MemoryMax=31G cap class).
set -uo pipefail
HERE=/home/dev/interfold-research/interfold/poc/r139
INTERFOLD=/home/dev/interfold-research/interfold
UNITDIR="$HOME/.config/systemd/user"
NARGO_BIN="$HOME/.local/bin/nargo"
BB_BIN="$HOME/.local/bin/bb"
log(){ echo "$(date -u +%H:%M:%S) $*" | tee -a "$HERE/leg2.log"; }
CFGC="$INTERFOLD/circuits/lib/src/configs/committee/active.nr"
CFGD="$INTERFOLD/circuits/lib/src/configs/default/mod.nr"
git -C "$INTERFOLD" checkout -- "$CFGC" "$CFGD"
{ sha256sum "$CFGC" "$CFGD" | cut -d' ' -f1; } > "$HERE/cfg2_pre.txt"
python3 - > "$HERE/flip2.log" 2>&1 <<'PY'
s="/home/dev/interfold-research/interfold/circuits/lib/src/configs/default/mod.nr"
b=open(s).read(); b2=b.replace('super::insecure::','super::secure::')
assert b!=b2, 'flip failed (already flipped?)'
open(s,'w').write(b2); print('config flipped insecure->secure (dkg preset only)')
PY
echo "flip rc=$?" >> "$HERE/flip2.log"
rm -rf "$HERE/c12/target" "$HERE/c12_run.out" "$HERE/c12_artifact.txt" "$HERE/c12_gates.json"
cat > "$HERE/leg_c12.sh" <<EOF
#!/usr/bin/env bash
set -u
cd "$HERE/c12" || exit 97
T0=\$(date +%s.%N)
taskset -c 0-3 "$NARGO_BIN" compile > "$HERE/c12_run.out" 2>&1
RC=\$?
T1=\$(date +%s.%N)
{ echo "T0=\$T0"; echo "T1=\$T1"; echo "NARGO_RC=\$RC"; } >> "$HERE/c12_run.out"
jj=\$(find target -name "*.json" 2>/dev/null | grep -v program | head -1)
echo "ARTIFACT=\$jj" > "$HERE/c12_artifact.txt"
[ -n "\$jj" ] && "$BB_BIN" gates -b "\$jj" -t noir-recursive-no-zk > "$HERE/c12_gates.json" 2>&1
exit 0
EOF
chmod +x "$HERE/leg_c12.sh"
{
  echo "[Unit]"
  echo "Description=r139 c12 per-cell-call slope middle probe"
  echo "[Service]"
  echo "Type=simple"
  echo "Environment=HOME=/home/dev LOGNAME=dev"
  echo "MemoryAccounting=yes"
  echo "MemoryMax=31G"
  echo "TimeoutStartSec=2400"
  echo "ExecStart=$HERE/leg_c12.sh"
} > "$UNITDIR/r139_c12.service"
systemctl --user daemon-reload >/dev/null 2>&1
systemctl --user start r139_c12 2>&1 | tee -a "$HERE/leg2.log"
log "launched r139_c12"
for i in $(seq 1 280); do [ "$(systemctl --user is-active r139_c12 2>/dev/null)" = "active" ] || break; sleep 10; done
log "r139_c12 ended=$(systemctl --user is-active r139_c12 2>/dev/null)"
git -C "$INTERFOLD" checkout -- "$CFGC" "$CFGD"
{ sha256sum "$CFGC" "$CFGD" | cut -d' ' -f1; } > "$HERE/cfg2_post.txt"
if diff -q "$HERE/cfg2_pre.txt" "$HERE/cfg2_post.txt" >/dev/null; then
  echo "CONFIG BYTE-RESTORED (sha equal)" > "$HERE/cfg2_restore.txt"
else
  echo "CONFIG RESTORE MISMATCH" > "$HERE/cfg2_restore.txt"
  cat "$HERE/cfg2_pre.txt" >> "$HERE/cfg2_restore.txt"
  cat "$HERE/cfg2_post.txt" >> "$HERE/cfg2_restore.txt"
fi
log "== LEG2 DONE $(date -u +%Y-%m-%dT%H:%M:%SZ) =="
[ -f "$HERE/c12_artifact.txt" ] && grep -q "ARTIFACT=.*\.json" "$HERE/c12_artifact.txt" || { log "c12 NO artifact"; exit 137; }
exit 0