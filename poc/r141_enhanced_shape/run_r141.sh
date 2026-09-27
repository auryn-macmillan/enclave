#!/usr/bin/env bash
# r141 — r140 re-gate option (a) SIZING: the enhanced (acc + parity / range)
# consumer cell shape vs the r137 w6 base twin, K=6, A production shape
# (secure-8192 N=8192, BIT_MSG=58), DKG-preset-only flip (r137 protocol).
# LEGS (each its own systemd --user unit, MemoryMax=31G, 4c-pinned taskset):
#   base    = verbatim r137 w6 twin (expect digit twin 16,409 g)
#   e_par   = base + ONE parity row per cell (producer H-row representation)
#   e_range = base + per-coeff range_check_standard (producer family,
#             SHARE_COMPUTATION_BIT_SHARE against the preset DKG q)
# DKG preset flip (insecure->secure) done BEFORE launch by the caller; this
# script only drives the units and then restores the config byte-sha.
set -uo pipefail
HERE=/home/dev/interfold-research/interfold/poc/r141_enhanced_shape
INTERFOLD=/home/dev/interfold-research/interfold
export PATH="$HOME/.local/bin:$HOME/.nargo/bin:$PATH"
BB="$HOME/.local/bin/bb"; NARGO="$HOME/.local/bin/nargo"
COMMITTEE="$INTERFOLD/circuits/lib/src/configs/committee/active.nr"
DEFAULTM="$INTERFOLD/circuits/lib/src/configs/default/mod.nr"
log(){ echo "$(date -u +%H:%M:%S) $*" | tee -a "$HERE/leg.log"; }

run_svc(){
  local leg="$1" unit="r141_${leg}"
  rm -rf "$HERE/$leg/target"
  cat > "${HOME}/.config/systemd/user/${unit}.service" <<EOF
[Unit]
Description=r141 ${leg} consumer-enhanced-shape sizing probe
[Service]
Type=exec
Environment=HOME=/home/dev LOGNAME=dev
MemoryAccounting=yes
MemoryMax=31G
TimeoutStartSec=1800
ExecStart=/bin/bash -c 'cd /home/dev/interfold-research/interfold/poc/r141_enhanced_shape/${leg} && taskset -c 0-3 $HOME/.local/bin/nargo compile 2>&1 | tee /home/dev/interfold-research/interfold/poc/r141_enhanced_shape/${leg}_run.out; jj=\$(find target -name "*.json" 2>/dev/null | grep -v program | head -1); echo "ARTIFACT=\$jj" > /home/dev/interfold-research/interfold/poc/r141_enhanced_shape/${leg}_artifact.txt; [ -n "\$jj" ] && $HOME/.local/bin/bb gates -b "\$jj" -t noir-recursive-no-zk > /home/dev/interfold-research/interfold/poc/r141_enhanced_shape/${leg}_gates.json 2>&1'
EOF
  systemctl --user daemon-reload >/dev/null 2>&1
  systemctl --user start "$unit" 2>&1 | tee -a "$HERE/leg.log"
  log "launched $unit"
}
wait_svc(){ local u="r141_$1" i; for i in $(seq 1 120); do [ "$(systemctl --user is-active "$u" 2>/dev/null)" = "active" ] || break; sleep 10; done; log "$u ended=$(systemctl --user is-active "$u" 2>/dev/null)"; }

for leg in base e_par e_range; do
  run_svc "$leg"; wait_svc "$leg";
  journalctl --user -u "r141_${leg}" --since "-1h" --no-pager 2>/dev/null | grep -E 'MemoryPeak|oom|Result=' | tail -5 >> "$HERE/leg.log"
done

git -C "$INTERFOLD" checkout -- "$COMMITTEE" "$DEFAULTM"
{ sha256sum "$COMMITTEE" "$DEFAULTM" | cut -d' ' -f1; } > "$HERE/cfg_post.txt"
if diff -q "$HERE/cfg_pre.txt" "$HERE/cfg_post.txt" >/dev/null 2>&1; then
  echo "CONFIG BYTE-RESTORED (sha equal)" > "$HERE/cfg_restore.txt"
else
  echo "CONFIG RESTORE MISMATCH: pre=" > "$HERE/cfg_restore.txt"
  cat "$HERE/cfg_pre.txt" >> "$HERE/cfg_restore.txt" 2>/dev/null
  cat "$HERE/cfg_post.txt" >> "$HERE/cfg_restore.txt"
fi
log "== DONE $(date -u +%H:%M:%SZ) =="
shutdown=0
for leg in base e_par e_range; do
  a="$HERE/${leg}_artifact.txt"
  if [ ! -f "$a" ] || ! grep -q "ARTIFACT=.*\.json" "$a"; then
    log "${leg} NO artifact"
    shutdown=137
  fi
done
exit $shutdown