#!/usr/bin/env bash
set -u
cd "/home/dev/interfold-research/interfold/poc/r143_rereg_walls/e_par24" || exit 97
export PATH="/home/dev/.local/bin:/home/dev/.opencode/bin:/home/dev/.local/bin:/home/dev/.local/bin:/home/dev/.local/bin:/home/dev/.opencode/bin:/home/dev/.hermes/hermes-agent/venv/bin:/home/dev/.hermes/hermes-agent/node_modules/.bin:/home/dev/.hermes/node/bin:/home/dev/.hermes/node:/home/dev/.local/bin:/home/dev/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"
T0=$(date +%s.%N)
taskset -c 0-3 "/home/dev/.local/bin/nargo" compile > "/home/dev/interfold-research/interfold/poc/r143_rereg_walls/e_par24_run.out" 2>&1
RC=$?
T1=$(date +%s.%N)
{ echo "T0=$T0"; echo "T1=$T1"; echo "NARGO_RC=$RC"; } >> "/home/dev/interfold-research/interfold/poc/r143_rereg_walls/e_par24_run.out"
jj=$(find target -name "*.json" 2>/dev/null | grep -v program | head -1)
echo "ARTIFACT=$jj" > "/home/dev/interfold-research/interfold/poc/r143_rereg_walls/e_par24_artifact.txt"
[ -n "$jj" ] && "/home/dev/.local/bin/bb" gates -b "$jj" -t noir-recursive-no-zk > "/home/dev/interfold-research/interfold/poc/r143_rereg_walls/e_par24_gates.json" 2>&1
exit 0
