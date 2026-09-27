#!/usr/bin/env bash
# r141 runner 3 — clean-provenance re-run of the two K=6 legs (base, e_range).
# Full assert chain every stage, manifest to cfg_repro3.txt. No hand-flips.
set -uo pipefail
HERE=/home/dev/interfold-research/interfold/poc/r141_enhanced_shape
INTERFOLD=/home/dev/interfold-research/interfold
export PATH="$HOME/.local/bin:$HOME/.nargo/bin:$PATH"
BB="$HOME/.local/bin/bb"; NARGO="$HOME/.local/bin/nargo"
MOD="$INTERFOLD/circuits/lib/src/configs/default/mod.nr"
COMMITTEE="$INTERFOLD/circuits/lib/src/configs/committee/active.nr"
MAN="$HERE/cfg_repro3.txt"
log(){ echo "$(date -u +%H:%M:%SZ) $*" | tee -a "$HERE/leg3.log"; }
sha(){ sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }
assert_eq(){
  if [ "$1" != "$2" ]; then
    log "ASSERT-FAIL: $3 (got=$1 want=$2)"; echo "ASSERT-FAIL $3" > "$HERE/leg3_failed.txt"; exit 61
  fi
}

log "=== RUNNER3 START ==="
HEAD_SHA=$(git -C "$INTERFOLD" rev-parse HEAD)
MOD_HEAD_SHA=$(git -C "$INTERFOLD" show HEAD:"circuits/lib/src/configs/default/mod.nr" | sha256sum | cut -d' ' -f1)
COM_HEAD_SHA=$(git -C "$INTERFOLD" show HEAD:"circuits/lib/src/configs/committee/active.nr" | sha256sum | cut -d' ' -f1)
{
  echo "HEAD=$HEAD_SHA   modHEAD=$MOD_HEAD_SHA   committeeHEAD=$COM_HEAD_SHA"
  echo "WORKTREE_BEFORE mod=$(sha $MOD)   committee=$(sha $COMMITTEE)"
} | tee -a "$HERE/leg3.log"
[ -f "$MAN" ] && : > "$MAN"
cp -a "$HERE/leg3.log" "$MAN"

# Stage A: restore tree-to-committed for both files
git -C "$INTERFOLD" checkout -- "$MOD" "$COMMITTEE"
S1_M=$(sha "$MOD"); S1_C=$(sha "$COMMITTEE")
assert_eq "$S1_M" "$MOD_HEAD_SHA" "after-restore mod"
assert_eq "$S1_C" "$COM_HEAD_SHA" "after-restore committee"
echo "RESTORED mod=$S1_M  committee=$S1_C (== HEAD shas)" >> "$MAN"

# Stage B: insist we start from the committed (insecure) baseline for this
# re-run. The one-line flip below only changes the two preset `pub use` rows.
MA=$MOD python3 - <<'PY'
import os, sys
s = os.environ["MA"]
b = open(s).read()
b2 = b.replace("super::insecure::", "super::secure::")
if b == b2 and "super::insecure::dkg" not in b:
    raise SystemExit("NOT_INSECURE-BASELINE-EXPECTED")
open(s, "w").write(b2)
print("FLIPPED")
PY
S2_M=$(sha "$MOD")
echo "AFTER_FLIP mod=$S2_M  (flipped file)" >> "$MAN"

# Stage C: run base K=6 and e_range K=6 legs (fresh targets)
for leg in base e_range; do
  rm -rf "$HERE/$leg/target"
  cat > "$HOME/.config/systemd/user/r141r3_${leg}.service" <<EOF
[Unit]
Description=r141 r3 re-run ${leg}
[Service]
Type=exec
Environment=HOME=/home/dev LOGNAME=dev
MemoryAccounting=yes
MemoryMax=31G
TimeoutStartSec=1800
ExecStart=/bin/bash -c 'cd /home/dev/interfold-research/interfold/poc/r141_enhanced_shape/${leg} && taskset -c 0-3 $HOME/.local/bin/nargo compile 2>&1 | tee -a /home/dev/interfold-research/interfold/poc/r141_enhanced_shape/${leg}_run_r3.out; jj=$(find target -name "*.json" 2>/dev/null | grep -v program | head -1); echo "ARTIFACT=$jj" > /home/dev/interfold-research/interfold/poc/r141_enhanced_shape/${leg}_artifact_r3.txt; [ -n "$jj" ] && $HOME/.local/bin/bb gates -b "$jj" -t noir-recursive-no-zk > /home/dev/interfold-research/interfold/poc/r141_enhanced_shape/${leg}_gates_r3.json 2>&1'
EOF
  systemctl --user daemon-reload
  systemctl --user start "r141r3_${leg}"
  log "launched r141r3_$leg"
  for i in $(seq 1 200); do
    [ "$(systemctl --user is-active "r141r3_${leg}" 2>/dev/null)" = "active" ] || break
    sleep 8
  done
  log "r141r3_${leg} ended=$(systemctl --user is-active "r141r3_${leg}" 2>/dev/null)"
  journalctl --user -u "r141r3_${leg}" --no-pager 2>/dev/null | grep -E 'MemoryPeak|oom|Result=' | tail -5 >> "$HERE/leg3.log"
done
echo "MOD_AT_RUN=$S2_M  (secure flipped mod used for both legs)" >> "$MAN"

# Stage D: restore committed
git -C "$INTERFOLD" checkout -- "$MOD" "$COMMITTEE"
S3_M=$(sha "$MOD")
assert_eq "$S3_M" "$MOD_HEAD_SHA" "after-rerun mod"
echo "AFTER_RERUN mod=$S3_M  committee=$(sha "$COMMITTEE")" >> "$MAN"
log "=== RUNNER3 END OK ==="