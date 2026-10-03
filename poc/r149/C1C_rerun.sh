#!/usr/bin/env bash
# r149 C1C RE-RUN (isolated per-limb slice leg; A_main C1A/C1B already RAN-landed)
set -u
export PATH="/usr/local/bin:$HOME/.local/bin:$HOME/.nargo/bin:$PATH"
R=/home/dev/interfold-research/interfold
OUT=$R/poc/r149
BIN=$R/circuits/bin/threshold
CIR="pk_generation"
DEF=$R/circuits/lib/src/configs/default/mod.nr
PK=$R/circuits/lib/src/core/threshold/pk_generation.nr
PRE3=$(sha256sum "$PK" | cut -d' ' -f1)
mlog(){ echo "[$(date -u +%FT%TZ)] $*"; }
cd "$R" || exit 1
cp -f "$DEF" "$OUT/rerun_default_mod.nr.bak"
cp -f "$PK"  "$OUT/rerun_pk_generation.nr.bak"

flip_preset(){
python3 - "$DEF" <<'PY'
import sys
p=sys.argv[1]
s=open(p).read()
a=s
s=s.replace('for preset: insecure-512','for preset: secure-8192')
s=s.replace('pub use super::insecure::dkg;','pub use super::secure::dkg;')
s=s.replace('pub use super::insecure::threshold;','pub use super::secure::threshold;')
assert a!=s, "no preset flip"
open(p,'w').write(s)
print("FLIP_PRESET_OK")
PY
}

# C1C splice (re-don per dry-run /tmp/r149_dry.py): the range fn's for-loop block is
# `for i in 0..L {` .. `            );\n        }\n` (25-char tail, includes the for
# close, NOT the fn close). The whole block gets swept as a comment - brace balance
# invariant because the block contains BOTH its open `{` and close `}`.
python3 - "$PK" <<'PY'
import sys
p=sys.argv[1]
s=open(p).read()
hd='        for i in 0..L {\n'
i0=s.find(hd)
assert i0!=-1, 'per-limb for-loop header not found'
hdr_end='            );\n        }\n'
e=s.find(hdr_end, i0)
assert e!=-1, 'for-loop tail anchor not found'
end_idx=e+len(hdr_end)
block=s[i0:end_idx]
# assert the block ends at the for-close '}', not one brace too far
assert block.rstrip('\n').endswith('}'), 'block tail unexpected: %r' % block.split('\n')[-2]
assert block.count('{')==1 and block.count('}')==1, 'splice unit must be brace-self-contained'
new='        // C1C-SHADOW-NOP-PER-LIMB-LOOP-BEGIN (r149 rerun)\n'
lines=block.split('\n')
if lines and lines[-1]=='':
    lines=lines[:-1]   # phantom elem from the trailing \n
for ln in lines:
    new += '        // ' + ln + '\n'
# do NOT rstrip - keeps a trailing \n so `s[end_idx:]` (starts `    }` = fn close)
# lands on its own line instead of being swallowed by the last comment
# (r147 C3C first-pass hit the same bug, re-reun; we avoid it up front).
s2=s[:i0]+new+s[end_idx:]
assert s2.count('C1C-SHADOW-NOP-PER-LIMB-LOOP-BEGIN')==1
# flat-keep invariants:
assert s2.count('self.eek.range_check_2bounds')==1
assert s2.count('self.sk.range_check_2bounds')==1
# alive per-limb headers: verify_evaluations keeps its own; the range one must be dead
alive=sum(1 for ln in s2.split('\n') if ln.lstrip().startswith('for i in 0..L {'))
assert alive==1, 'verify_evaluations for-loop must be sole alive occurrence; got %d' % alive
# file-level brace invariant
assert s2.count('{')==s.count('{') and s2.count('}')==s.count('}')
open(p,'w').write(s2)
print('NOP_C1C_OK (per-limb for-loop block cut; eek/sk flat + verify_evaluations intact)')
PY

flip_preset
cd "$BIN/$CIR" || exit 97
(mkdir -p "$OUT/rerun_target_snap" && tar -cf "$OUT/rerun_target_snap/threshold_target_pre.tar" -C "$BIN" target) 2>/dev/null
PRE_PIN=$(sha256sum "$BIN/target/$CIR.json" 2>/dev/null | cut -d' ' -f1)
rm -f "$BIN/target/$CIR.json"
mlog "C1C_RERUN_COMPILE_START PRE_PIN=$PRE_PIN PRE_SHA_PK=$PRE3"
(  while :; do
      awk '/^MemTotal:/{t=$2} /^MemAvailable:/{a=$2} END{printf "%d\n",(t-a)/1024}' /proc/meminfo
      sleep 8
    done
) > "$OUT/C1C_ram_trace_rerun.log" 2>/dev/null &
SAMP=$!
taskset -c 0-3 /usr/bin/time -v nargo compile --force > "$OUT/C1C_rerun_compile_stdout.log" 2> "$OUT/C1C_rerun_compile_timev.log"
RC=$?
echo "COMPILE_RC=$RC" >> "$OUT/C1C_rerun_compile_timev.log"
kill $SAMP 2>/dev/null; wait $SAMP 2>/dev/null
mlog "C1C_RERUN_COMPILE_RC=$RC"

# FRESH CAPTURE BEFORE RESTORE (1st rerun bug: copy-post-restore reused the in-tree artifact)
if grep -q "COMPILE_RC=0" "$OUT/C1C_rerun_compile_timev.log" && [ -f "$BIN/target/$CIR.json" ]; then
  cp -f "$BIN/target/$CIR.json" "$OUT/C1C_rerun_fresh.json"
  cp -f "$OUT/C1C_rerun_fresh.json" "$OUT/C1C_fresh.json"
  sha256sum "$OUT/C1C_rerun_fresh.json" | cut -d' ' -f1 > "$OUT/C1C_fresh_sha.txt"
  mlog "C1C_RERUN_FRESH_SHA=$(cat "$OUT/C1C_fresh_sha.txt")"
  bb gates -b "$OUT/C1C_rerun_fresh.json" -t noir-recursive-no-zk > "$OUT/C1C_gates_raw.json" 2> "$OUT/C1C_gates_err.log"
  python3 - "$OUT" <<'PY'
import json, sys
out = sys.argv[1]
d = json.load(open(f"{out}/C1C_gates_raw.json"))
fns = d.get("functions", [])
gates = sum(f.get("circuit_size", 0) for f in fns)
acir = sum(f.get("acir_opcodes", 0) for f in fns)
open(f"{out}/C1C_gates_summary.json","w").write(json.dumps({"gates":gates,"acir":acir,"nfns":len(fns)}))
print(f"C1C_GATES_SUMMARY gates={gates} acir={acir} nfns={len(fns)}")
PY
fi

# restore source + target
cp -f "$OUT/rerun_pk_generation.nr.bak" "$PK"
cp -f "$OUT/rerun_default_mod.nr.bak" "$DEF"
rm -rf "$BIN/target" && (cd "$BIN" && tar -xf "$OUT/rerun_target_snap/threshold_target_pre.tar")

RC_END=$(sed -n 's/^COMPILE_RC=//p' "$OUT/C1C_rerun_compile_timev.log" | tail -1)
PEAK=$(grep "Maximum resident" "$OUT/C1C_rerun_compile_timev.log" | awk '{print $NF}')
WALL=$(grep -E 'Elapsed \(wall clock\)?' "$OUT/C1C_rerun_compile_timev.log" | head -1 | sed -E 's/.*: //')
POST=$(cat "$OUT/C1C_fresh_sha.txt" 2>/dev/null)
GATES=$(python3 -c "import json;print(json.load(open('$OUT/C1C_gates_summary.json'))['gates'])" 2>/dev/null || echo gates_n/a)
ACIR=$(python3 -c "import json;print(json.load(open('$OUT/C1C_gates_summary.json'))['acir'])" 2>/dev/null || echo acir_n/a)
SWAP=$(grep -E '^Swaps:' "$OUT/C1C_rerun_compile_timev.log" | awk '{print $NF}')
SPEAK=$(sort -n "$OUT/C1C_ram_trace_rerun.log" 2>/dev/null | tail -1)
RESTORED_PK=$(sha256sum "$PK" | cut -d' ' -f1)
RESTORED_DEF=$(sha256sum "$DEF" | cut -d' ' -f1)
{
  echo "ROUND=r149 LEG=C1C DATE=$(date -u +%FT%TZ) (rerun - C1C first-attempt failed at brace splice)"
  echo "COMPILE_RC=$RC_END"
  echo "PEAK_RSS_KB=$PEAK SWAPS=${SWAP:-0}"
  echo "WALL_TIME=$WALL"
  echo "FRESH_SHA256=$POST PRE_SHA_PK=$PRE3"
  echo "GATES=$GATES GOLDEN_EXPECTED=UNANCHORED-SHADOW-NOP-LEG"
  echo "ACIR_OPS=$ACIR"
  echo "SAMPLED_PEAK_MB_THIS_LEG=${SPEAK:-0}"
  echo "RESTORED_PK_SHA=$RESTORED_PK (expected=$PRE3)"
  echo "RESTORED_DEF_SHA=$RESTORED_DEF"
} > "$OUT/C1C.r149"
mlog "C1C_RERUN_END $RC_END $PEAK $WALL $GATES PRE=$PRE3 RESTORED=$RESTORED_PK"
exit 0