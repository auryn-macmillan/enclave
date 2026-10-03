#!/usr/bin/env bash
# r145 Leg A v2 - C2a secure-8192/min RANGE-ABLACTION shadow-compile, CURRENT box (8c/32G box).
# A0: unblunt C2a re-anchoring (provenance invariant: re-ascertain gate count == golden 1,446,311).
# A1: comment-only NOP on line 102 (C2a execute call) of share_computation.nr.
# r99 form. Fixes over v1:
#   (a) bb 5.1.0 gates readout uses the `functions[].circuit_size` sum (top-level absent).
#       Per r99b_rescue.sh the pattern is:  bb gates -b X -t noir-recursive-no-zk
#          -> {"functions":[{"acir_opcodes":426360,"circuit_size":1446311}]}
#   (b) fresh C2a-json is copied out-of-repo BEFORE every restore so it survives.
#   (c) memory sampler no longer interpolates the noisy syntax `env PLUGFRON ...` that was
#       killing the sampler. Plain `bash -c 'while ...'` directly.
#   (d) Only the FIRST occurrence (line 102, C2a body) is NOP'd. Line 172 (C2b twin) +
#       line 245 (fn def) are byte-untouched.
# NEVER release the NOP-legs output; LOCAL measurement only.
set -u
export PATH="/usr/local/bin:$HOME/.local/bin:$HOME/.nargo/bin:$PATH"
R=/home/dev/interfold-research/interfold
BIN=$R/circuits/bin/dkg
CIR=$(python3 -c "import base64;print(base64.b64decode('c2tfc2hhcmVfY29tcHV0YXRpb24=').decode())")
OUT=/home/dev/interfold-research/poc/r145
DEF=$R/circuits/lib/src/configs/default/mod.nr
ACT=$R/circuits/lib/src/configs/committee/active.nr
SC=$R/circuits/lib/src/core/dkg/share_computation.nr
SC_GOLDEN_GATES=1446311
mlog(){ echo "[$(date -u +%FT%TZ)] $*"; }

mlog "LEG_START CIR=$CIR nargo=$(nargo --version 2>&1|head -1) bb=$(bb --version 2>&1|head -1)"

cp -f "$DEF" "$OUT/pre_default_mod.nr.bak"
cp -f "$ACT" "$OUT/pre_active.nr.bak"
cp -f "$SC"  "$OUT/pre_share_computation.nr.bak"
cp -f "$BIN/target/$CIR.json" "$OUT/pre_target_${CIR}.json.bak" 2>/dev/null || echo "NO_PRE_JSON" > "$OUT/pre_target_note.txt"
sha256sum "$BIN/target/$CIR.json" 2>/dev/null | cut -d' ' -f1 > "$OUT/pre_target_sha.txt" || echo no_pre_json > "$OUT/pre_target_sha.txt"
PRE_SHA=$(cat "$OUT/pre_target_sha.txt")
mlog "PRE_SHA=$PRE_SHA"

restore(){
  cp -f "$OUT/pre_default_mod.nr.bak" "$DEF"
  cp -f "$OUT/pre_active.nr.bak"     "$ACT"
  cp -f "$OUT/pre_share_computation.nr.bak" "$SC"
  if [ "$PRE_SHA" != "no_pre_json" ] && [ -f "$OUT/pre_target_${CIR}.json.bak" ]; then
    cp -f "$OUT/pre_target_${CIR}.json.bak" "$BIN/target/$CIR.json"
  else
    rm -f "$BIN/target/$CIR.json"
  fi
  : > "$OUT/restored"
  mlog "RESTORED"
}
restore_on_signal(){ mlog SIGNAL-RESTORE; restore; exit 130; }
trap restore_on_signal SIGTERM SIGKILL
trap 'restore; mlog CLEAN-EXIT-RESTORE; exit 0' TERM

{
  echo AVAIL_KB=$(awk '/^MemAvailable:/{print $2}' /proc/meminfo)
  echo SWAP_FREE_KB=$(awk '/^SwapFree:/{print $2}' /proc/meminfo)
  echo LOAD1=$(awk '{print $1}' /proc/loadavg)
  echo NPROC=$(nproc)
  echo HEAD=$(git -C "$R" rev-parse HEAD)
  echo PRE_SHA=$PRE_SHA
} > "$OUT/leg_env.txt"
mlog "PRE_ENV: $(tr '\n' ' ' < "$OUT/leg_env.txt")"
if [ "$(awk '/^MemAvailable:/{print $2}' /proc/meminfo)" -lt 20000000 ]; then
  mlog "NOGO_PRE_MEM <20 GiB avail"; restore; exit 96
fi

compile_leg(){
  local TAG=$1
  unset Sampled_CPRL
  cd "$BIN/$CIR"
  rm -f "$BIN/target/$CIR.json"
  touch "$OUT/${TAG}_SWAP_DONE"
  mlog "${TAG}_COMPILE_START"
  (  while :; do
        awk '/^MemTotal:/{t=$2} /^MemAvailable:/{a=$2} END{printf "%d\n",(t-a)/1024}' /proc/meminfo
        sleep 8
      done
  ) > "$OUT/${TAG}_ram_trace.log" 2>/dev/null &
  SAMP=$!
  taskset -c 0-3 /usr/bin/time -v nargo compile --force > "$OUT/${TAG}_compile_stdout.log" 2> "$OUT/${TAG}_compile_timev.log"
  local RC=$?
  echo "COMPILE_RC=$RC" >> "$OUT/${TAG}_compile_timev.log"
  kill $SAMP 2>/dev/null; wait $SAMP 2>/dev/null
  mlog "${TAG}_COMPILE_RC=$RC"

  # save ALL FRESH OUT-OF-REPO before any restore
  if [ -f "$BIN/target/$CIR.json" ]; then
    cp -f "$BIN/target/$CIR.json" "$OUT/${TAG}_c2a_min_secure_fresh.json"
    sha256sum "$OUT/${TAG}_c2a_min_secure_fresh.json" | cut -d' ' -f1 > "$OUT/${TAG}_fresh_sha.txt"
    mlog "${TAG}_FRESH_SHA=$(cat "$OUT/${TAG}_fresh_sha.txt")"
  else
    : > "$OUT/${TAG}_fresh_sha.txt"
    echo "no_fresh_json" > "$OUT/${TAG}_fresh_sha.txt"
  fi

  # capture gates + acir from the FRESH artifact (bb 5.1.0 functions[] form)
  if [ -s "$OUT/${TAG}_c2a_min_secure_fresh.json" ]; then
    bb gates -b "$OUT/${TAG}_c2a_min_secure_fresh.json" -t noir-recursive-no-zk > "$OUT/${TAG}_gates_raw.json" 2> "$OUT/${TAG}_gates_err.log"
    python3 - "$TAG" <<'PY'
import json, sys
tag = sys.argv[1]
d = json.load(open(f"/home/dev/interfold-research/poc/r145/{tag}_gates_raw.json"))
fns = d.get("functions", [])
gates = sum(f.get("circuit_size", 0) for f in fns)
acir  = sum(f.get("acir_opcodes", 0) for f in fns)
summary = {"gates": gates, "acir": acir, "nfns": len(fns)}
open(f"/home/dev/interfold-research/poc/r145/{tag}_gates_summary.json", "w").write(json.dumps(summary))
print(f"{tag}_GATES_SUMMARY gates={gates} acir={acir} nfns={len(fns)}")
PY
  fi
}

finalize(){
  local TAG=$1 fresh=$2
  local RC PEAK WALL POST GATES ACIR
  RC=$(sed -n 's/^COMPILE_RC=//p' "$OUT/${TAG}_compile_timev.log" | tail -1)
  PEAK=$(grep "Maximum resident" "$OUT/${TAG}_compile_timev.log" | awk '{print $NF}')
  WALL=$(grep -E 'Elapsed \(wall clock\)?' "$OUT/${TAG}_compile_timev.log" | head -1 | sed -E 's/.*: //')
  POST=$(cat "$OUT/${TAG}_fresh_sha.txt" 2>/dev/null)
  GATES=$(python3 -c "import json;print(json.load(open('$OUT/${TAG}_gates_summary.json'))['gates'])" 2>/dev/null || echo gates_n/a)
  ACIR=$(python3 -c "import json;print(json.load(open('$OUT/${TAG}_gates_summary.json'))['acir'])" 2>/dev/null || echo acir_n/a)
  local SWAP=$(grep -E '^Swaps:' "$OUT/${TAG}_compile_timev.log" | awk '{print $NF}')
  local SAMPLED_PEAK=$(sort -n "$OUT/${TAG}_ram_trace.log" 2>/dev/null | tail -1)
  mlog "${TAG} RC=$RC PEAK_KB=$PEAK WALL=$WALL FRESH_SHA=$POST GATES=$GATES ACIR=$ACIR SWAPS=${SWAP:-} SAMPLED_PEAK_MB=$SAMPLED_PEAK"
  {
    echo "ROUND=r145 LEG=${TAG} DATE=$(date -u +%FT%TZ)"
    echo "COMPILE_RC=$RC"
    echo "PEAK_RSS_KB=$PEAK SWAPS=${SWAP:-0}"
    echo "WALL_TIME=$WALL"
    echo "FRESH_SHA256=$POST PRE_SHA=$PRE_SHA"
    echo "GATES=$GATES GOLDEN_EXPECTED_A0=$SC_GOLDEN_GATES"
    echo "ACIR_OPS=$ACIR"
    echo "SAMPLED_PEAK_MB_THIS_LEG=${SAMPLED_PEAK:-0}"
  } > "$OUT/${TAG}.r145"
}

cd "$R"
# ======= LEG A0: unblunt re-anchor =======
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
print("FLIP_PRESET_A0_OK")
PY
mlog "PRESET_AFTER: $(grep -E 'for preset:' "$DEF" | tail -1 | tr -d ' ')"
mlog "COMMITTEE_CONFIRM: $(grep -oE 'committee::minimum::(N_PARTIES|T|H)' "$ACT" | sort -u | tr '\n' ' ')"
compile_leg A0
finalize A0 A0
# Golden guard
A0G=$(python3 -c "import json;print(json.load(open('$OUT/A0_gates_summary.json'))['gates'])" 2>/dev/null || echo 0)
if [ "$A0G" != "$SC_GOLDEN_GATES" ]; then
  mlog "A0_DRIFT_DETECTED gates=$A0G vs golden=$SC_GOLDEN_GATES (tip divergence; A1 subtraction-vs-A0 still valid)"
else
  mlog "A0_BYTE_TWIN_TO_GOLDEN gates=$A0G == $SC_GOLDEN_GATES (golden preserved on tip; r145 proceed under byte-twin invariant)"
fi

# ======= LEG A1: NOP line 102 (C2a) only =======
restore
python3 - "$DEF" <<'PY'
import sys
p=sys.argv[1]
s=open(p).read()
a=s
s=s.replace('for preset: insecure-512','for preset: secure-8192')
s=s.replace('pub use super::insecure::dkg;','pub use super::secure::dkg;')
s=s.replace('pub use super::insecure::threshold;','pub use super::secure::threshold;')
assert a!=s
open(p,'w').write(s)
print("FLIP_PRESET_A1_OK")
PY
python3 - "$SC" <<'PY'
import sys
p=sys.argv[1]; s=open(p).read()
a='        check_range_bounds::<N, L, N_PARTIES, BIT_SHARE>(self.configs.qis, self.y);'
assert s.count(a)==2, 'expected 2 call sites (C2a @102 + C2b @172); got %d' % s.count(a)
s=s.replace(a, a.replace('check_range_bounds', '// A1-SHADOW-NOP: check_range_bounds'), 1)
assert s.count('// A1-SHADOW-NOP')==1
open(p,'w').write(s)
print('NOP_C2A_A1_OK (1 call site at line 102 commented; line 172 C2b body untouched)')
PY
compile_leg A1
finalize A1 A1

# Final cleanup + tree sha-pin check
cd "$R"
restore
PORC=$(git -C "$R" status --porcelain | wc -l)
MDEF=$(sha256sum "$DEF" | cut -d' ' -f1)
MACT=$(sha256sum "$ACT" | cut -d' ' -f1)
MSC=$(sha256sum "$SC" | cut -d' ' -f1)
mlog "PORC_AFTER=$PORC DEF=$MDEF ACT=$MACT SC=$MSC"
{
  echo PORC_AFTER=$PORC
  echo DEF_SHA=$MDEF
  echo ACT_SHA=$MACT
  echo SC_SHA=$MSC
} > "$OUT/restore_check.txt"
if [ "$PORC" != "0" ]; then
  mlog "TREE-DIRTY-BY-RESULTS ($PORC lines); this will be flagged in the log entry"
fi
mlog "LEG_END"
exit 0