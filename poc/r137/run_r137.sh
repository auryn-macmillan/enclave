#!/usr/bin/env bash
# r137 — consumer cheap-verify slope at the A production shape (recursive
# per-cell probe; r132 p3-class body with SAFE sponge DROPPED). K=6 (RAN
# twin of r135 v3s 16,409 g gate), K=12 (fresh 2-pt interior), K=42 (the
# 42-cell blob that OOM'd r135 leg-3 at 30.73 GiB cgroup peak). Sequential,
# each leg under its own systemd --user unit with MemoryMax=31G (the 26-28
# GiB unit cap in r126/r135 is too tight for the 42-cell unbound-wires
# class — the v3-1 blob peaked 30.73 GB cgroup at H14). Flip = DKG-preset
# only (insecure->secure), committee minimum. 4c-pinned.
set -uo pipefail
HERE=/home/dev/interfold-research/interfold/poc/r137
INTERFOLD=/home/dev/interfold-research/interfold
export PATH="$HOME/.local/bin:$HOME/.nargo/bin:$PATH"
BB="$HOME/.local/bin/bb"; NARGO="$HOME/.local/bin/nargo"
[ -x "$NARGO" ] || NARGO="$HOME/.nargo/bin/nargo"
COMMITTEE="$INTERFOLD/circuits/lib/src/configs/committee/active.nr"
DEFAULTM="$INTERFOLD/circuits/lib/src/configs/default/mod.nr"
log(){ echo "$(date -u +%H:%M:%S) $*" | tee -a "$HERE/leg.log"; }
git -C "$INTERFOLD" checkout -- "$COMMITTEE" "$DEFAULTM"
{ sha256sum "$COMMITTEE" "$DEFAULTM" | cut -d' ' -f1; } > "$HERE/cfg7_pre.txt"
{ echo "== r137 box census $(date -u +%Y-%m-%dT%H:%M:%SZ) =="
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

run_svc(){
  local K="$1" unit="r137_w${K}"
  rm -rf "$HERE/w${K}/target"
  cat > "${HOME}/.config/systemd/user/${unit}.service" <<EOF
[Unit]
Description=r137 w${K} consumer-cheap-verify slope probe
[Service]
Type=exec
Environment=HOME=/home/dev LOGNAME=dev
MemoryAccounting=yes
MemoryMax=31G
TimeoutStartSec=600
ExecStart=/bin/bash -c 'cd /home/dev/interfold-research/interfold/poc/r137/w${K} && taskset -c 0-3 $HOME/.local/bin/nargo compile 2>&1 | tee /home/dev/interfold-research/interfold/poc/r137/w${K}_run.out; jj=\$(find target -name "*.json" 2>/dev/null | grep -v program | head -1); echo "ARTIFACT=\$jj" > /home/dev/interfold-research/interfold/poc/r137/w${K}_artifact.txt; [ -n "\$jj" ] && $HOME/.local/bin/bb gates -b "\$jj" -t noir-recursive-no-zk > /home/dev/interfold-research/interfold/poc/r137/w${K}_gates.json 2>&1'
EOF
  systemctl --user daemon-reload >/dev/null 2>&1
  systemctl --user start "${unit}" 2>&1 | tee -a "$HERE/leg.log"
  log "launched ${unit}"
}
wait_svc(){ local u="r137_w$1" i; for i in $(seq 1 60); do [ "$(systemctl --user is-active "$u" 2>/dev/null)" = "active" ] || break; sleep 10; done; log "$u ended=$(systemctl --user is-active "$u" 2>/dev/null)"; }
for K in 6 12 42; do
  run_svc "$K"; wait_svc "$K";
done

git -C "$INTERFOLD" checkout -- "$COMMITTEE" "$DEFAULTM"
{ sha256sum "$COMMITTEE" "$DEFAULTM" | cut -d' ' -f1; } > "$HERE/cfg7_post.txt"
if diff -q "$HERE/cfg7_pre.txt" "$HERE/cfg7_post.txt" >/dev/null; then
  echo "CONFIG BYTE-RESTORED (sha equal)" > "$HERE/cfg7_restore.txt"
else
  echo "CONFIG RESTORE MISMATCH: pre=" > "$HERE/cfg7_restore.txt"
  cat "$HERE/cfg7_pre.txt" >> "$HERE/cfg7_restore.txt"
  cat "$HERE/cfg7_post.txt" >> "$HERE/cfg7_restore.txt"
fi
log "== DONE $(date -u +%Y-%m-%dT%H:%M:%SZ) =="
shutdown=0
for K in 6 12 42; do
  a="$HERE/w${K}_artifact.txt"
  if [ ! -f "$a" ] || ! grep -q "ARTIFACT=.*\.json" "$a"; then
    log "w${K} NO artifact"
    shutdown=137
  fi
done
exit $shutdown