#!/usr/bin/env bash
# r139 - per-cell INSTANTIATION form of the consumer cheap-verify body at
# the A shape (K=6 + K=42 explicit verify_cell calls; the r137 membrane nail
# shape the in-tree C4 diff must use). Sequential, each leg under its own
# systemd --user unit MemoryMax=31G (the ~4 GiB terminal-worker cgroup
# ceiling class, r126/r130). DKG-preset-only flip (insecure->secure);
# 4c-pinned taskset. Self-restoring config with sha-assert on restore.
set -uo pipefail
HERE=/home/dev/interfold-research/interfold/poc/r139
INTERFOLD=/home/dev/interfold-research/interfold
UNITDIR="$HOME/.config/systemd/user"
NARGO_BIN="$HOME/.local/bin/nargo"
BB_BIN="$HOME/.local/bin/bb"
log(){ echo "$(date -u +%H:%M:%S) $*" | tee -a "$HERE/leg.log"; }
CFGC="$INTERFOLD/circuits/lib/src/configs/committee/active.nr"
CFGD="$INTERFOLD/circuits/lib/src/configs/default/mod.nr"
git -C "$INTERFOLD" checkout -- "$CFGC" "$CFGD"
{ sha256sum "$CFGC" "$CFGD" | cut -d' ' -f1; } > "$HERE/cfg_pre.txt"
{ echo "== r139 box census $(date -u +%Y-%m-%dT%H:%M:%SZ) =="
  echo "nproc=$(nproc)"; grep -E 'MemTotal|MemAvailable|SwapTotal' /proc/meminfo
  cat /proc/loadavg; git -C "$INTERFOLD" rev-parse HEAD; git -C "$INTERFOLD" rev-parse origin/main
} > "$HERE/box_census.txt"
python3 - > "$HERE/flip.log" 2>&1 <<'PY'
s="/home/dev/interfold-research/interfold/circuits/lib/src/configs/default/mod.nr"
b=open(s).read(); b2=b.replace('super::insecure::','super::secure::')
assert b!=b2, 'flip failed (already flipped?)'
open(s,'w').write(b2); print('config flipped insecure->secure (dkg preset only)')
PY
echo "flip rc=$?" >> "$HERE/flip.log"

gen_leg(){
  # $1 = K. Writes a small self-contained wrapper script + unit file.
  local K="$1" unit="r139_f${K}" vdir="$HERE/f${K}"
  cat > "$HERE/leg_f${K}.sh" <<EOF
#!/usr/bin/env bash
set -u
cd "$vdir" || exit 97
T0=\$(date +%s.%N)
taskset -c 0-3 "$NARGO_BIN" compile > "$HERE/f${K}_run.out" 2>&1
RC=\$?
T1=\$(date +%s.%N)
{ echo "T0=\$T0"; echo "T1=\$T1"; echo "NARGO_RC=\$RC"; } >> "$HERE/f${K}_run.out"
jj=\$(find target -name "*.json" 2>/dev/null | grep -v program | head -1)
echo "ARTIFACT=\$jj" > "$HERE/f${K}_artifact.txt"
[ -n "\$jj" ] && "$BB_BIN" gates -b "\$jj" -t noir-recursive-no-zk > "$HERE/f${K}_gates.json" 2>&1
exit 0
EOF
  chmod +x "$HERE/leg_f${K}.sh"
  {
    echo "[Unit]"
    echo "Description=r139 f${K} per-cell-call consumer cheap-verify probe"
    echo "[Service]"
    echo "Type=simple"
    echo "Environment=HOME=/home/dev LOGNAME=dev"
    echo "MemoryAccounting=yes"
    echo "MemoryMax=31G"
    echo "TimeoutStartSec=2400"
    echo "ExecStart=$HERE/leg_f${K}.sh"
  } > "$UNITDIR/${unit}.service"
}

wait_svc(){ local u="r139_f$1" i; for i in $(seq 1 280); do [ "$(systemctl --user is-active "$u" 2>/dev/null)" = "active" ] || break; sleep 10; done; log "$u ended=$(systemctl --user is-active "$u" 2>/dev/null)"; }
for K in 6 42; do
  rm -rf "$HERE/f${K}/target" "$HERE/f${K}_run.out" "$HERE/f${K}_artifact.txt" "$HERE/f${K}_gates.json"
  gen_leg "$K"
  systemctl --user daemon-reload >/dev/null 2>&1
  systemctl --user start "r139_f${K}" 2>&1 | tee -a "$HERE/leg.log"
  log "launched r139_f${K}"
  wait_svc "$K"
done

git -C "$INTERFOLD" checkout -- "$CFGC" "$CFGD"
{ sha256sum "$CFGC" "$CFGD" | cut -d' ' -f1; } > "$HERE/cfg_post.txt"
if diff -q "$HERE/cfg_pre.txt" "$HERE/cfg_post.txt" >/dev/null; then
  echo "CONFIG BYTE-RESTORED (sha equal)" > "$HERE/cfg_restore.txt"
else
  echo "CONFIG RESTORE MISMATCH: pre=" > "$HERE/cfg_restore.txt"
  cat "$HERE/cfg_pre.txt" >> "$HERE/cfg_restore.txt"
  cat "$HERE/cfg_post.txt" >> "$HERE/cfg_restore.txt"
fi
log "== DONE $(date -u +%Y-%m-%dT%H:%M:%SZ) =="
shutdown=0
for K in 6 42; do
  a="$HERE/f${K}_artifact.txt"
  if [ ! -f "$a" ] || ! grep -q "ARTIFACT=.*\.json" "$a"; then
    log "f${K} NO artifact"
    shutdown=137
  fi
done
exit $shutdown