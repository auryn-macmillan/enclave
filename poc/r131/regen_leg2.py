#!/usr/bin/env python3
# Regenerate run_leg2.sh cleanly (prior write arrived scrambled).
sh = r'''#!/bin/bash
# r131 second leg: node-cost probes (np2 = 2-elem SAFE node hash, np3 = 3-elem) at the
# same secure-8192/small field as leg 1, 4c-pinned, wall via `time -v`.
set -o pipefail
RT=/home/dev/interfold-research/interfold/poc/r131
cd /home/dev/interfold-research/interfold || exit 1
CFG1="circuits/lib/src/configs/committee/active.nr"
CFG2="circuits/lib/src/configs/default/mod.nr"
C1=$(sha256sum "$CFG1" | cut -d' ' -f1)
C2=$(sha256sum "$CFG2" | cut -d' ' -f1)
echo "leg2 start $(date -u +%FT%T) cfg1=$C1 cfg2=$C2" >> "$RT/leg2_status.log"
restore() { sed -i 's/committee::small::N_PARTIES/committee::minimum::N_PARTIES/g; s/committee::small::T/committee::minimum::T/g' "$CFG1"; sed -i 's/configs::secure/USE configs::insecure/g' "$CFG2"; echo "config restored min->insecure $(date -u +%FT%T)" >> "$RT/flip.log"; }
trap restore EXIT
sed -i 's/committee::minimum::N_PARTIES/committee::small::N_PARTIES/g; s/committee::minimum::T/committee::small::T/g' "$CFG1"
sed -i 's/USE configs::insecure/USE configs::secure/g' "$CFG2"
echo "config flipped min->small, insecure->secure" >> "$RT/flip.log"
for pair in np2 np3; do
  path="$RT/$pair"
  start=$(date +%s)
  taskset -c 0-3 timeout 420 /usr/bin/time -v stdbuf -oL -eL nargo compile "$path" > "$RT/${pair}_run.out" 2>&1
  rc=$?
  end=$(date +%s)
  echo "${pair} wall=$((end-start))s nargo_rc=$rc" >> "$RT/leg2_status.log"
  if [ $rc -eq 0 ]; then
    nargo gates "$path" -o "$RT/${pair}_gates.json" 2> "$RT/${pair}_gates.stderr"
    grep -o '"circuit_size": [0-9]*' "$RT/${pair}_gates.json" | head -2
  fi
done
echo "== LEG2 END $(date -u +%FT%T) ==" >> "$RT/leg2_status.log"
'''
open('/home/dev/interfold-research/interfold/poc/r131/run_leg2.sh', 'w').write(sh)
print('WROTE leg2', len(sh))