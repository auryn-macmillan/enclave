#!/usr/bin/env bash
set -u
cd "/home/dev/interfold-research/interfold/poc/r139/c48" || exit 97
T0=$(date +%s.%N)
taskset -c 0-3 "/home/dev/.local/bin/nargo" compile > "/home/dev/interfold-research/interfold/poc/r139/c48_run.out" 2>&1
RC=$?
T1=$(date +%s.%N)
{ echo "T0=$T0"; echo "T1=$T1"; echo "NARGO_RC=$RC"; } >> "/home/dev/interfold-research/interfold/poc/r139/c48_run.out"
jj=$(find target -name "*.json" 2>/dev/null | grep -v program | head -1)
echo "ARTIFACT=$jj" > "/home/dev/interfold-research/interfold/poc/r139/c48_artifact.txt"
[ -n "$jj" ] && "/home/dev/.local/bin/bb" gates -b "$jj" -t noir-recursive-no-zk > "/home/dev/interfold-research/interfold/poc/r139/c48_gates.json" 2>&1
exit 0
