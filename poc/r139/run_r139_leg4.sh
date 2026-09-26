#!/usr/bin/env bash
# r139 leg 4 - c48 probe only (membrane pin between c24 RAN-GREEN and f42 OOM).
set -uo pipefail
HERE=/home/dev/interfold-research/interfold/poc/r139
INTERFOLD=/home/dev/interfold-research/interfold
UNITDIR="$HOME/.config/systemd/user"
NARGO_BIN="$HOME/.local/bin/nargo"
BB_BIN="$HOME/.local/bin/bb"
log(){ echo "$(date -u +%H:%M:%S) $*" | tee -a "$HERE/leg4.log"; }
CFGC="$INTERFOLD/circuits/lib/src/configs/committee/active.nr"
CFGD="$INTERFOLD/circuits/lib/src/configs/default/mod.nr"
git -C "$INTERFOLD" checkout -- "$CFGC" "$CFGD"
{ sha256sum "$CFGC" "$CFGD" | cut -d' ' -f1; } > "$HERE/cfg4_pre.txt"
python3 - > "$HERE/flip4.log" 2>&1 <<'PY'
s="/home/dev/interfold-research/interfold/circuits/lib/src/configs/default/mod.nr"
b=open(s).read(); b2=b.replace('super::insecure::','super::secure::')
assert b!=b2, 'flip failed (already flipped?)'
open(s,'w').write(b2); print('config flipped insecure->secure (dkg preset only)')
PY
echo "flip rc=$?" >> "$HERE/flip4.log"
rm -rf "$HERE/c48/target" "$HERE/c48_run.out" "$HERE/c48_artifact.txt" "$HERE/c48_gates.json"
cat > "$HERE/leg_c48.sh" <<EOF
#!/usr/bin/env bash
set -u
cd "$HERE/c48" || exit 97
T0=\$(date +%s.%N)
taskset -c 0-3 "$NARGO_BIN" compile > "$HERE/c48_run.out" 2>&1
RC=\$?
T1=\$(date +%s.%N)
{ echo "T0=\$T0"; echo "T1=\$T1"; echo "NARGO_RC=\$RC"; } >> "$HERE/c48_run.out"
jj=\$(find target -name "*.json" 2>/dev/null | grep -v program | head -1)
echo "ARTIFACT=\$jj" > "$HERE/c48_artifact.txt"
[ -n "\$jj" ] && "$BB_BIN" gates -b "\$jj" -t noir-recursive-no-zk > "$HERE/c48_gates.json" 2>&1
exit 0
EOF
chmod +x "$HERE/leg_c48.sh"
{
  echo "[Unit]"
  echo "Description=r139 c48 per-cell-call membrane pin probe"
  echo "[Service]"
  echo "Type=simple"
  echo "Environment=HOME=/home/dev LOGNAME=dev"
  echo "MemoryAccounting=yes"
  echo "MemoryMax=31G"
  echo "TimeoutStartSec=2400"
  echo "ExecStart=$HERE/leg_c48.sh"
} > "$UNITDIR/r139_c48.service"
systemctl --user daemon-reload >/dev/null 2>&1
systemctl --user start r139_c48 2>&1 | tee -a "$HERE/leg4.log"
log "launched r139_c48"
for i in $(seq 1 280); do [ "$(systemctl --user is-active r139_c48 2>/dev/null)" = "active" ] || break; sleep 10; done
log "r139_c48 ended=$(systemctl --user is-active r139_c48 2>/dev/null)"
journalctl --user -u r139_c48 --no-pager 2>/dev/null | grep -E 'Consumed' | tail -1 > "$HERE/c48_journal.txt"
git -C "$INTERFOLD" checkout -- "$CFGC" "$CFGD"
{ sha256sum "$CFGC" "$CFGD" | cut -d' ' -f1; } > "$HERE/cfg4_post.txt"
if diff -q "$HERE/cfg4_pre.txt" "$HERE/cfg4_post.txt" >/dev/null; then
  echo "CONFIG BYTE-RESTORED (sha equal)" > "$HERE/cfg4_restore.txt"
else
  echo "CONFIG RESTORE MISMATCH" > "$HERE/cfg4_restore.txt"
  cat "$HERE/cfg4_pre.txt" >> "$HERE/cfg4_restore.txt"
  cat "$HERE/cfg4_post.txt" >> "$HERE/cfg4_restore.txt"
fi
log "== LEG4 DONE $(date -u +%Y-%m-%dT%H:%M:%SZ) =="
status="0"
if [ ! -f "$HERE/c48_artifact.txt" ] || ! grep -q "ARTIFACT=.*\.json" "$HERE/c48_artifact.txt"; then
  log "c48 NO artifact (OOM or fail class - expected possible)"
  status=138
fi
exit $status