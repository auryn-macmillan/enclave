#!/usr/bin/env bash
# r133 control leg 2 (b5/b6): the SHIP SHAPE — 30-leaf depth-5 tree.
set -uo pipefail
HERE=/home/dev/interfold-research/interfold/poc/r133
INTERFOLD=/home/dev/interfold-research/interfold
export PATH="$HOME/.local/bin:$HOME/.nargo/bin:$PATH"
BB="$HOME/.local/bin/bb"
COMMITTEE=circuits/lib/src/configs/committee/active.nr
DEFAULTM=circuits/lib/src/configs/default/mod.nr
git -C "$INTERFOLD" checkout -- "$COMMITTEE" "$DEFAULTM" 2>/dev/null || true
{ sha256sum "$INTERFOLD/$COMMITTEE" "$INTERFOLD/$DEFAULTM" | cut -d' ' -f1; } > "$HERE/cfg_pre_c.txt"
python3 /tmp/r133flip/flip.py > "$HERE/flip_c.log" 2>&1
echo "flip rc=$?" >> "$HERE/flip_c.log"
for n in b5 b6; do
  rm -rf "$INTERFOLD/poc/r133/$n/target"
  ( cd "$INTERFOLD/poc/r133/$n" && taskset -c 0-3 /usr/bin/time -v stdbuf -oL -eL nargo compile ) > "$HERE/${n}_run.out" 2>&1
  echo "${n} compile rc=$? $(date -u +%H:%M:%S)" | tee -a "$HERE/leg_status_c.log"
  JJ=$(find "$INTERFOLD/poc/r133/$n/target" -name '*.json' 2>/dev/null | head -1)
  if [ -n "$JJ" ]; then
    "$BB" gates -b "$JJ" -t noir-recursive-no-zk > "$HERE/${n}_gates.json" 2>&1
    echo "${n} gates rc=$? $(date -u +%H:%M:%S)" | tee -a "$HERE/leg_status_c.log"
    cp "$JJ" "$HERE/${n}_artifact.json" 2>/dev/null || true
  else
    echo "${n} NO artifact" | tee -a "$HERE/leg_status_c.log"
  fi
done
git -C "$INTERFOLD" checkout -- "$COMMITTEE" "$DEFAULTM"
{ sha256sum "$INTERFOLD/$COMMITTEE" "$INTERFOLD/$DEFAULTM" | cut -d' ' -f1; } > "$HERE/cfg_post_c.txt"
diff "$HERE/cfg_pre_c.txt" "$HERE/cfg_post_c.txt" > "$HERE/cfg_restore_c.txt" 2>&1 \
  && echo "CONFIG BYTE-RESTORED (sha equal)" >> "$HERE/cfg_restore_c.txt" \
  || echo "CONFIG RESTORE MISMATCH" >> "$HERE/cfg_restore_c.txt"
echo "== DONE $(date -u +%Y-%m-%dT%H:%M:%SZ) ==" | tee -a "$HERE/leg_status_c.log"