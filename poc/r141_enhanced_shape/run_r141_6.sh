#!/usr/bin/env bash
# r141 runner 6 (final). Per-leg systemd user units (MemoryMax=31G, taskset
# 0-3), config locked to one sha for the whole sweep, per-leg manifest.
# Pushes provenance hard: HEAD sha + commit-sha + pre-flip sha + sweep-sha
# + per-leg post-run sha + CCOUNT from a digest of the .nr sources.
set -uo pipefail
HERE=/home/dev/interfold-research/interfold/poc/r141_enhanced_shape
INTERFOLD=/home/dev/interfold-research/interfold
export PATH="$HOME/.local/bin:$HOME/.nargo/bin:$PATH"
NARGO="$HOME/.local/bin/nargo"; BB="$HOME/.local/bin/bb"
MOD="$INTERFOLD/circuits/lib/src/configs/default/mod.nr"
MAN="$HERE/RUN6_MANIFEST.txt"; LOG="$HERE/leg6.log"; : > "$MAN"; : > "$LOG"
log(){ printf '[%s] %s\n' "$(date -u +%H:%M:%SZ)" "$*" | tee -a "$LOG" >/dev/null; }
sha(){ sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }

HSHA=$(git -C "$INTERFOLD" rev-parse HEAD)
OSHA=$(git -C "$INTERFOLD" show HEAD:circuits/lib/src/configs/default/mod.nr | sha256sum | cut -d' ' -f1)
SRC_DIGEST=$(cd "$HERE" && sha256sum base/src/main.nr e_par/src/main.nr e_par12/src/main.nr e_range/src/main.nr e_range12/src/main.nr 2>&1 | sha256sum | cut -d' ' -f1)
log "HEAD=$HSHA committed_mod=$OSHA src_digest=$SRC_DIGEST"

# Restore committed, then lock to secure
git -C "$INTERFOLD" checkout -- "$MOD"
if grep -q 'super::insecure::dkg' "$MOD"; then
  cp "$MOD" "$HERE/mod_nr_backup_run6.nr"
  sed -i 's/super::insecure::dkg/super::secure::dkg/; s/super::insecure::threshold/super::secure::threshold/' "$MOD"
fi
SSHA=$(sha "$MOD")
PRES=$(grep -m1 'pub use super::secure::dkg\|pub use super::insecure::dkg' "$MOD")
echo "SWEEP_SHA=$SSHA  HEAD=$HSHA  COMMITTED=$OSHA  PRESET=$PRES  SRCDIGEST=$SRC_DIGEST" >> "$MAN"
[ "$SSHA" != "$OSHA" ] || { log "FATAL: sweep sha equals committed sha (flip did not land)"; exit 61; }

for LEG in base e_par e_par12 e_range e_range12; do
  SUB="$HERE/$LEG"
  [ -f "$SUB/src/main.nr" ] || { log "SKIP $LEG"; continue; }
  UNIT="r141r6_${LEG}"
  rm -rf "$SUB/target"
  K=$(grep -oE 'Polynomial<N>; [0-9]+' "$SUB/src/main.nr" | head -1 | grep -oE '[0-9]+')
  cat > "$HOME/.config/systemd/user/${UNIT}.service" <<EOF
[Unit]
Description=r141 r6 ${LEG}
[Service]
Type=exec
Environment=HOME=/home/dev LOGNAME=dev
MemoryAccounting=yes
MemoryMax=31G
TimeoutStartSec=1800
ExecStart=/bin/bash -c 'cd $SUB && taskset -c 0-3 /home/dev/.local/bin/nargo compile 2>&1 | tee -a $HERE/${LEG}_run_r6.out; jj=$(find target -name "*.json" 2>/dev/null | grep -v program | head -1); if [ -n "$jj" ]; then /home/dev/.local/bin/bb gates -b "$jj" -t noir-recursive-no-zk > $HERE/${LEG}_gates_r6.json 2>&1; echo "ARTIFACT=$jj" > $HERE/${LEG}_artifact_r6.txt; else echo "NO_ARTIFACT" > $HERE/${LEG}_artifact_r6.txt; fi'
EOF
  systemctl --user daemon-reload
  systemctl --user start "$UNIT"
  log "LAUNCH $UNIT (K=$K) pre_sha=$(sha $MOD)"
  for i in $(seq 1 240); do
    [ "$(systemctl --user is-active "$UNIT" 2>/dev/null)" = "active" ] || break
    sleep 8
  done
  STATUS=$(systemctl --user is-active "$UNIT" 2>/dev/null)
  MEM=$(journalctl --user -u "$UNIT" --no-pager 2>/dev/null | grep -oE 'MemoryPeak=[^ ]+' | tail -1)
  RC=$(journalctl --user -u "$UNIT" --no-pager 2>/dev/null | grep -oE 'Result=[a-z]+' | tail -1)
  SZ=$(grep -oE '"circuit_size": [0-9]+' "$HERE/${LEG}_gates_r6.json" 2>/dev/null | head -1 | grep -oE '[0-9]+')
  AC=$(grep -oE '"acir_opcodes": [0-9]+' "$HERE/${LEG}_gates_r6.json" 2>/dev/null | head -1 | grep -oE '[0-9]+')
  POST_SHA=$(sha $MOD)
  log "DONE $LEG status=$STATUS ${RC} ${MEM} circuit=$SZ acir=$AC post_sha=$POST_SHA"
  printf 'LEG=%s K=%s status=%s %s %s circuit=%s acir=%s sweep_sha=%s post_sha=%s\n' \
    "$LEG" "$K" "$STATUS" "$RC" "$MEM" "$SZ" "$AC" "$SSHA" "$POST_SHA" >> "$MAN"
done

git -C "$INTERFOLD" checkout -- "$MOD"
ESHA=$(sha $MOD)
[ "$ESHA" = "$OSHA" ] && log "RUN6 END OK (restored to committed)" || log "RUN6 END-LEAK $ESHA != $OSHA"
echo "END_OK=$([ "$ESHA" = "$OSHA" ] && echo YES || echo NO)" >> "$MAN"