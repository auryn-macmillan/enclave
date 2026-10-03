#!/usr/bin/env bash
# r146 - C3 + C2b secure-8192/min RANGE-ABLACTION shadow-compiles (r145 NEXT; queue item (1)).
# r99/r100/r145 form. Four legs, one artifact per leg:
#   C3A : share_encryption unblunt re-anchor (golden 2,966,353 g; r39/r41/r75/r84)
#   C3B : share_encryption with ShareEncryption::check_range_bounds() call NOP-ed
#   C2BA: e_sm_share_computation unblunt re-anchor (golden 2,888,964 g; r45/r100)
#   C2BB: e_sm_share_computation with the 2nd call site (line 172, C2b body) NOP-ed
# Measurement ONLY. NEVER release a NOP-leg artifact. Tree restored byte-exact after each leg.
set -u
export PATH="/usr/local/bin:$HOME/.local/bin:$HOME/.nargo/bin:$PATH"
R=/home/dev/interfold-research/interfold
OUT=/home/dev/interfold-research/interfold/poc/r146
BIN=$R/circuits/bin/dkg
CIR3="share_encryption"
CIRB="e_sm_share_computation"
DEF=$R/circuits/lib/src/configs/default/mod.nr
ACT=$R/circuits/lib/src/configs/committee/active.nr
SC=$R/circuits/lib/src/core/dkg/share_computation.nr
SE=$R/circuits/lib/src/core/dkg/share_encryption.nr
G3=2966353
GB=2888964
mlog(){ echo "[$(date -u +%FT%TZ)] $*"; }

cd "$R" || exit 1
mkdir -p "$OUT"
mlog "LEG_START nargo=$(nargo --version 2>&1|head -1) bb=$(bb --version 2>&1|head -1) HEAD=$(git -C "$R" rev-parse HEAD)"

cp -f "$DEF" "$OUT/pre_default_mod.nr.bak"
cp -f "$ACT" "$OUT/pre_active.nr.bak"
cp -f "$SC"  "$OUT/pre_share_computation.nr.bak"
cp -f "$SE"  "$OUT/pre_share_encryption.nr.bak"
cp -f "$BIN/target/$CIR3.json" "$OUT/pre_target_share_encryption.json.bak" 2>/dev/null || true
cp -f "$BIN/target/$CIRB.json" "$OUT/pre_target_esm.json.bak" 2>/dev/null || true
P3=$(sha256sum "$BIN/target/$CIR3.json" 2>/dev/null | cut -d' ' -f1 || echo no_pre_json)
PB=$(sha256sum "$BIN/target/$CIRB.json" 2>/dev/null | cut -d' ' -f1 || echo no_pre_json)
mlog "PRE_SHA3=$P3 PRE_SHAB=$PB"

restore(){
  cp -f "$OUT/pre_default_mod.nr.bak"        "$DEF"
  cp -f "$OUT/pre_active.nr.bak"             "$ACT"
  cp -f "$OUT/pre_share_computation.nr.bak"  "$SC"
  cp -f "$OUT/pre_share_encryption.nr.bak"   "$SE"
  if [ "$P3" != "no_pre_json" ] && [ -f "$OUT/pre_target_share_encryption.json.bak" ]; then
    cp -f "$OUT/pre_target_share_encryption.json.bak" "$BIN/target/$CIR3.json"
  else
    rm -f "$BIN/target/$CIR3.json"
  fi
  if [ "$PB" != "no_pre_json" ] && [ -f "$OUT/pre_target_esm.json.bak" ]; then
    cp -f "$OUT/pre_target_esm.json.bak" "$BIN/target/$CIRB.json"
  else
    rm -f "$BIN/target/$CIRB.json"
  fi
  mlog "RESTORED"
}
restore_on_signal(){ mlog SIGNAL-RESTORE; restore; exit 130; }
trap restore_on_signal TERM INT

{
  echo AVAIL_KB=$(awk '/^MemAvailable:/{print $2}' /proc/meminfo)
  echo SWAP_FREE_KB=$(awk '/^SwapFree:/{print $2}' /proc/meminfo)
  echo LOAD1=$(awk '{print $1}' /proc/loadavg)
  echo NPROC=$(nproc)
  echo HEAD=$(git -C "$R" rev-parse HEAD)
  echo PRE_SHA3=$P3
  echo PRE_SHAB=$PB
} > "$OUT/leg_env.txt"
mlog "PRE_ENV: $(tr '\n' ' ' < "$OUT/leg_env.txt")"
if [ "$(awk '/^MemAvailable:/{print $2}' /proc/meminfo)" -lt 20000000 ]; then
  mlog "NOGO_PRE_MEM <20 GiB avail"; restore; exit 96
fi

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

compile_leg(){
  local TAG=$1 CIR=$2
  cd "$BIN/$CIR" || { mlog "$TAG CD_FAIL"; restore; exit 97; }
  rm -f "$BIN/target/$CIR.json"
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

  # save ALL FRESH OUT-OF-LEG before any restore
  if [ -f "$BIN/target/$CIR.json" ]; then
    cp -f "$BIN/target/$CIR.json" "$OUT/${TAG}_fresh.json"
    sha256sum "$OUT/${TAG}_fresh.json" | cut -d' ' -f1 > "$OUT/${TAG}_fresh_sha.txt"
    mlog "${TAG}_FRESH_SHA=$(cat "$OUT/${TAG}_fresh_sha.txt")"
  else
    echo "no_fresh_json" > "$OUT/${TAG}_fresh_sha.txt"
  fi

  if [ -s "$OUT/${TAG}_fresh.json" ]; then
    bb gates -b "$OUT/${TAG}_fresh.json" -t noir-recursive-no-zk > "$OUT/${TAG}_gates_raw.json" 2> "$OUT/${TAG}_gates_err.log"
    python3 - "$OUT" "$TAG" <<'PY'
import json, sys
out, tag = sys.argv[1], sys.argv[2]
d = json.load(open(f"{out}/{tag}_gates_raw.json"))
fns = d.get("functions", [])
gates = sum(f.get("circuit_size", 0) for f in fns)
acir  = sum(f.get("acir_opcodes", 0) for f in fns)
open(f"{out}/{tag}_gates_summary.json","w").write(json.dumps({"gates":gates,"acir":acir,"nfns":len(fns)}))
print(f"{tag}_GATES_SUMMARY gates={gates} acir={acir} nfns={len(fns)}")
PY
  fi
  cd "$R"
}

finalize(){
  local TAG=$1 GOLDEN=$2
  local RC PEAK WALL POST GATES ACIR SWAP SPEAK
  RC=$(sed -n 's/^COMPILE_RC=//p' "$OUT/${TAG}_compile_timev.log" | tail -1)
  PEAK=$(grep "Maximum resident" "$OUT/${TAG}_compile_timev.log" | awk '{print $NF}')
  WALL=$(grep -E 'Elapsed \(wall clock\)?' "$OUT/${TAG}_compile_timev.log" | head -1 | sed -E 's/.*: //')
  POST=$(cat "$OUT/${TAG}_fresh_sha.txt" 2>/dev/null)
  GATES=$(python3 -c "import json;print(json.load(open('$OUT/${TAG}_gates_summary.json'))['gates'])" 2>/dev/null || echo gates_n/a)
  ACIR=$(python3 -c "import json;print(json.load(open('$OUT/${TAG}_gates_summary.json'))['acir'])" 2>/dev/null || echo acir_n/a)
  SWAP=$(grep -E '^Swaps:' "$OUT/${TAG}_compile_timev.log" | awk '{print $NF}')
  SPEAK=$(sort -n "$OUT/${TAG}_ram_trace.log" 2>/dev/null | tail -1)
  mlog "${TAG} RC=$RC PEAK_KB=$PEAK WALL=$WALL FRESH_SHA=$POST GATES=$GATES ACIR=$ACIR SWAPS=${SWAP:-none} SAMPLED_PEAK_MB=${SPEAK:-0}"
  if [ "$GATES" != "$GOLDEN" ] && [ "${GOLDEN%UNANCHORED*}" != "$GOLDEN" ]; then
    mlog "${TAG}_GATES_VS_GOLDEN gates=$GATES golden=$GOLDEN"
  fi
  {
    echo "ROUND=r146 LEG=${TAG} DATE=$(date -u +%FT%TZ)"
    echo "COMPILE_RC=$RC"
    echo "PEAK_RSS_KB=$PEAK SWAPS=${SWAP:-0}"
    echo "WALL_TIME=$WALL"
    echo "FRESH_SHA256=$POST PRE_SHA3=$P3 PRE_SHAB=$PB"
    echo "GATES=$GATES GOLDEN_EXPECTED=$GOLDEN"
    echo "ACIR_OPS=$ACIR"
    echo "SAMPLED_PEAK_MB_THIS_LEG=${SPEAK:-0}"
  } > "$OUT/${TAG}.r146"
}

# ================= LEG C3A: share_encryption unblunt re-anchor =================
flip_preset
mlog "PRESET_AFTER: $(grep -E 'for preset:' "$DEF" | tail -1 | tr -d ' ')"
mlog "COMMITTEE_CONFIRM: $(grep -oE 'committee::minimum::(N_PARTIES|T|H)' "$ACT" | sort -u | tr '\n' ' ')"
compile_leg C3A "$CIR3"
finalize C3A "$G3"
restore

# ================= LEG C3B: share_encryption range-NOP (line 277) =================
flip_preset
python3 - "$SE" <<'PY'
import sys
p=sys.argv[1]; s=open(p).read()
a='        self.check_range_bounds();'
assert s.count(a)==1, 'expected exactly 1 call site in share_encryption.nr; got %d' % s.count(a)
s=s.replace(a, '// C3B-SHADOW-NOP: self.check_range_bounds();')
assert s.count('C3B-SHADOW-NOP')==1
open(p,'w').write(s)
print('NOP_C3B_OK (ShareEncryption::check_range_bounds call commented)')
PY
compile_leg C3B "$CIR3"
finalize C3B UNANCHORED-NOP-LEG
restore

# ================= LEG C2BA: e_sm_share_computation unblunt re-anchor =================
flip_preset
compile_leg C2BA "$CIRB"
finalize C2BA "$GB"
restore

# ================= LEG C2BB: e_sm share_computation 2nd call site (line 172, C2b) NOP =================
flip_preset
python3 - "$SC" <<'PY'
import sys
p=sys.argv[1]; s=open(p).read()
a='        check_range_bounds::<N, L, N_PARTIES, BIT_SHARE>(self.configs.qis, self.y);'
i1=s.find(a); i2=s.find(a, i1+1) if i1!=-1 else -1
assert i1!=-1 and i2!=-1, 'expected 2 call sites (C2a @102 + C2b @172); got %d' % (s.count(a))
nop=a.replace('check_range_bounds', '// C2BB-SHADOW-NOP: check_range_bounds')
s=s[:i2] + nop + s[i2+len(a):]
assert s.count('C2BB-SHADOW-NOP')==1 and s.count('C2BB-SHADOW-NOP')==1
open(p,'w').write(s)
print('NOP_C2BB_OK (2nd call site @ line 172 commented; C2a @102 untouched)')
PY
compile_leg C2BB "$CIRB"
finalize C2BB UNANCHORED-NOP-LEG
restore

# ================= TREE PIN CHECK =================
PORC=$(git -C "$R" status --porcelain | wc -l)
MDEF=$(sha256sum "$DEF" | cut -d' ' -f1)
MACT=$(sha256sum "$ACT" | cut -d' ' -f1)
MSC=$(sha256sum "$SC" | cut -d' ' -f1)
MSE=$(sha256sum "$SE" | cut -d' ' -f1)
mlog "PORC_AFTER=$PORC DEF=$MDEF ACT=$MACT SC=$MSC SE=$MSE"
{
  echo PORC_AFTER=$PORC
  echo DEF_SHA=$MDEF
  echo ACT_SHA=$MACT
  echo SC_SHA=$MSC
  echo SE_SHA=$MSE
} > "$OUT/restore_check.txt"
if [ "$PORC" != "0" ]; then
  mlog "TREE-DIRTY-BY-RESULTS ($PORC lines); flagged in log entry"
fi
mlog "LEG_END"
exit 0