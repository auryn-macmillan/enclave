#!/bin/bash
set -uo pipefail
export PATH="$HOME/.local/bin:$HOME/.nargo/bin:$PATH"
cd /home/dev/interfold-research/interfold/poc/r131
for p in np2 np3; do
  JJ=$(find $p/target -name '*.json' 2>/dev/null | head -1)
  if [ -z "$JJ" ]; then echo "$p NO-ARTIFACT"; continue; fi
  bb gates -b "$JJ" -t noir-recursive-no-zk > ${p}_gates.json 2>&1
  echo "$p rc=$? $(grep -oE '"circuit_size": [0-9]+|"acir_opcodes": [0-9]+' ${p}_gates.json | tr '\n' ' ')"
done