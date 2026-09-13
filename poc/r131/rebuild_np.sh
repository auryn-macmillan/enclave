#!/bin/bash
set -uo pipefail
export PATH="$HOME/.local/bin:$HOME/.nargo/bin:$PATH"
cd /home/dev/interfold-research/interfold/poc/r131
for p in np2 np3; do
  (cd $p && rm -rf target && nargo compile >/dev/null 2>&1)
  echo "$p compile rc=$?"
done
bash gate_np.sh