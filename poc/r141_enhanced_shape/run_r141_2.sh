#!/usr/bin/env bash
# r141 runner 2 — secure-preset legs (e_par K=6, e_par12 K=12, e_range12 K=12).
# CALLER RESPONSIBILITY: the DKG-preset flip (insecure->secure) is ALREADY done
# and cfg_pres2.txt holds the post-flip sha. This script does NOT flip; it
# restores the INSECURE baseline at the end (pre-round state) and sha-asserts.
set -uo pipefail
HERE=/home/dev/interfold-research/interfold/poc/r141_enhanced_shape
INTERFOLD=/home/dev/interfold-research/interfold
export PATH="$HOME/.local/bin:$HOME/.nargo/bin:$PATH"
BB="$HOME/.local/bin/bb"; NARGO="$HOME/.local/bin/nargo"
COMMITTEE="$INTERFOLD/circuits/lib/src/configs/committee/active.nr"
DEFAULTM="$INTERFOLD/circuits/lib/src/configs/default/mod.nr"
log(){ echo "$(date -u +%H:%M:%S) $*" | tee -a "$HERE/leg2.log"; }

run_svc(){
  local leg="$1" unit="r141_${leg}"
  rm -rf "$HERE/$leg/target"
  cat > "${HOME}/.config/systemd/user/${unit}.service" <<EOF
[Unit]
Description=r141 ${leg} consumer-enhanced-shape sizing probe (secure preset)
[Service]
Type=exec
Environment=HOME=/home/dev LOGNAME=dev
MemoryAccounting=yes
MemoryMax=31G
TimeoutStartSec=1800
ExecStart=/bin/bash -c 'cd /home/dev/interfold-research/interfold/poc/r141_enhanced_shape/${leg} && taskset -c 0-3 $HOME/.local/bin/nargo compile 2>&1 | tee /home/dev/interfold-research/interfold/poc/r141_enhanced_shape/${leg}_run.out; jj=\$(find target -name "*.json" 2>/dev/null | grep -v program | head -1); echo "ARTIFACT=\$jj" > /home/dev/interfold-research/interfold/poc/r141_enhanced_shape/${leg}_artifact.txt; [ -n "\$jj" ] && $HOME/.local/bin/bb gates -b "\$jj" -t noir-recursive-no-zk > /home/dev/interfold-research/interfold/poc/r141_enhanced_shape/${leg}_gates.json 2>&1'
EOF
  systemctl --user daemon-reload >/dev/null 2>&1
  systemctl --user start "$unit" 2>&1 | tee -a "$HERE/leg2.log"
  log "launched $unit"
}
wait_svc(){ local u="r141_$1" i; for i in $(seq 1 120); do [ "$(systemctl --user is-active "$u" 2>/dev/null)" = "active" ] || break; sleep 10; done; log "$u ended=$(systemctl --user is-active "$u" 2>/dev/null)"; }

for leg in e_par e_par12 e_range12; do
  run_svc "$leg"; wait_svc "$leg"
  journalctl --user -u "r141_${leg}" --no-pager 2>/dev/null | grep -E 'MemoryPeak|oom|Result=' | tail -5 >> "$HERE/leg2.log"
done

# restore INSECURE baseline (pre-round committed state = cfg_pre.txt), sha-assert
git -C "$INTERFOLD" checkout -- "$COMMITTEE" "$DEFAULTM"
{ sha256sum "$COMMITTEE" "$DEFAULTM" | cut -d' ' -f1; } > "$HERE/cfg_post2.txt"
if diff -q "$HERE/cfg_pre.txt" "$HERE/cfg_post2.txt" >/dev/null 2>&1; then
  echo "CONFIG RESTORED TO INSECURE BASELINE (sha equal to cfg_pre)" > "$HERE/cfg_restore2.txt"
else
  { echo "CONFIG RESTORE MISMATCH — cfg_pre (pre-round) vs cfg_post2:";
    echo "pre:";  cat "$HERE/cfg_pre.txt";
    echo "restored:"; cat "$HERE/cfg_post2.txt"; } > "$HERE/cfg_restore2.txt"
fi
log "== DONE2 $(date -u +%H:%M:%SZ) =="
shutdown=0
for leg in e_par e_par12 e_range12; do
  a="$HERE/${leg}_artifact.txt"
  if [ ! -f "$a" ] || ! grep -q "ARTIFACT=.*\.json" "$a"; then
    log "${leg} NO artifact"
    shutdown=137
  fi
done
exit $shutdown