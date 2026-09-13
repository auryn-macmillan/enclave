#!/bin/bash
# r131 third leg: re-compile the FIXED c4_v2 floor arm (type fix: decrypted_shares[0]),
# same protocol (4c-pinned, config flip restore, bb gates). ~2 min.
set -uo pipefail
RT=/home/dev/interfold-research/interfold/poc/r131
INTERFOLD=/home/dev/interfold-research/interfold
export PATH="$HOME/.local/bin:$HOME/.nargo/bin:$PATH"
BB="$HOME/.local/bin/bb"
cd "$INTERFOLD" || exit 1
COMMITTEE=circuits/lib/src/configs/committee/active.nr
DEFAULTM=circuits/lib/src/configs/default/mod.nr
restore() { git -C "$INTERFOLD" checkout -- "$COMMITTEE" "$DEFAULTM" 2>/dev/null || true; }
trap restore EXIT
cat > /tmp/r131_flip3.py <<'PYEOF'
c='circuits/lib/src/configs/committee/active.nr'; s='circuits/lib/src/configs/default/mod.nr'
a=open(c).read(); b=open(s).read()
a2=a.replace('committee::minimum','committee::small')
b2=b.replace('super::insecure::','super::secure::')
assert a!=a2 and b!=b2, 'flip failed'
open(c,'w').write(a2); open(s,'w').write(b2)
print('config flipped min->small, insecure->secure (leg3)')
PYEOF
python3 /tmp/r131_flip3.py >> "$RT/flip.log" 2>&1
DIR=$INTERFOLD/poc/r131/v2
rm -rf "$DIR/target"
( cd "$DIR" && taskset -c 0-3 /usr/bin/time -v stdbuf -oL -eL nargo compile ) > "$RT/c4_v2_run.out" 2>&1
rc=$?
echo "c4_v2 compile rc=$rc" >> "$RT/leg_status.log"
JJ=$(find "$DIR/target" -name '*.json' 2>/dev/null | head -1)
if [ -n "$JJ" ]; then
  "$BB" gates -b "$JJ" -t noir-recursive-no-zk > "$RT/c4_v2_gates.json" 2>&1
  echo "c4_v2 gates rc=$? artifact=$(basename "$JJ")" >> "$RT/leg_status.log"
  cp "$JJ" "$RT/c4_v2_artifact.json"
fi
git -C "$INTERFOLD" checkout -- "$COMMITTEE" "$DEFAULTM"
git -C "$INTERFOLD" status --porcelain
echo "== CG-3 DONE $(date -u +%H:%M:%S) ==" >> "$RT/leg_status.log"