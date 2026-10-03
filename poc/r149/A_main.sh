#!/usr/bin/env bash
# r149 - C1 pk_generation range-family cost-price (DIRECTION 2026-10-02 organization: C1 is the last UNPRICED large leaf: 2,223,114 g = 19.23% of the 11,558,499 g DKG base, r44/r75 digit-pinned).
# Same proven shape as r99/r100/r145/r146/r147: systemd user unit MemoryMax=31G, taskset 0-3, box 8c/32GiB/0swap, nargo 1.0.0-beta.26 + bb 5.1.0, secure-8192/minimum (N=3/T=1/H=2, L=3 pure-CRT).
# r44/C1 ferment: peak RSS 4,285 MB ring-511 min -> RR-class-safe.
#
# Legs (measurement only; NEVER release; tree restore per-leg byte-exact):
#   C1A  unblunt lower C1 re-anchor (golden 2,223,114 g; r44/r75 class committee-invariant)
#   C1B  PkGeneration::perform_range_checks() full NOP -> whole-facing family
#   C1C  keep 2 flat checks (eek, sk), hand-comment per-limb 'for i in 0..L' loop (e_sm/r1/r2 across L=3) -> per-limb slice (the part a r115-C6 aggregate redesign treats)
#
# Prediction: per-leg wall ~2:00-2:30 (golden r44 min 2:01); 3 legs + overhead < 15 min compute.
# NOT a sound vehicle - measurement only. Recover per-leg. Compute ceiling 45 min.
set -u
export PATH="/usr/local/bin:$HOME/.local/bin:$HOME/.nargo/bin:$PATH"
R=/home/dev/interfold-research/interfold
OUT=$R/poc/r149
BIN=$R/circuits/bin/threshold
CIR="pk_generation"
DEF=$R/circuits/lib/src/configs/default/mod.nr
ACT=$R/circuits/lib/src/configs/committee/active.nr
PK=$R/circuits/lib/src/core/threshold/pk_generation.nr
GOLDEN_C1=2223114
mlog(){ echo "[$(date -u +%FT%TZ)] $*"; }

cd "$R" || exit 1
mkdir -p "$OUT"
mlog "LEG_START nargo=$(nargo --version 2>&1|head -1) bb=$(bb --version 2>&1|head -1) HEAD=$(git -C \"$R\" rev-parse HEAD)"

cp -f "$DEF" "$OUT/pre_default_mod.nr.bak"
cp -f "$ACT" "$OUT/pre_active.nr.bak"
cp -f "$PK"  "$OUT/pre_pk_generation.nr.bak"
# artifact conservation (r73 class): the in-tree C1 target may hold signed/vk artifacts
(mkdir -p "$OUT/target_snap" && tar -cf "$OUT/target_snap/threshold_target_pre.tar" -C "$BIN" target) 2>/dev/null
sha256sum "$BIN/target/pk_generation.json" 2>/dev/null | cut -d' ' -f1 > "$OUT/pre_pkgen_json_sha.txt"
PRE3=$(sha256sum "$PK" | cut -d' ' -f1)
mlog "PRE_SHA_PK=$PRE3 PREHEAD=$(git -C "$R" rev-parse HEAD)"

restore(){
  cp -f "$OUT/pre_default_mod.nr.bak" "$DEF"
  cp -f "$OUT/pre_active.nr.bak"     "$ACT"
  cp -f "$OUT/pre_pk_generation.nr.bak" "$PK"
  # byte-restore the in-tree target dir (r73 conservation class)
  rm -rf "$BIN/target" && (cd "$BIN" && tar -xf "$OUT/target_snap/threshold_target_pre.tar")
  : > "$OUT/restored"
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
  echo PRE_SHA_PK=$PRE3
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

  # fixate-predictor: the artifact lives in BIN/target/. Recover OUT before restore touches target.
  if [ -f "$BIN/target/$CIR.json" ]; then
    cp -f "$BIN/target/$CIR.json" "$OUT/${TAG}_fresh.json"
    sha256sum "$OUT/${TAG}_fresh.json" | cut -d' ' -f1 > "$OUT/${TAG}_fresh_sha.txt"
    mlog "${TAG}_FRESH_SHA=$(cat \"$OUT/${TAG}_fresh_sha.txt\")"
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
    echo "ROUND=r149 LEG=${TAG} DATE=$(date -u +%FT%TZ)"
    echo "COMPILE_RC=$RC"
    echo "PEAK_RSS_KB=$PEAK SWAPS=${SWAP:-0}"
    echo "WALL_TIME=$WALL"
    echo "FRESH_SHA256=$POST PRE_SHA_PK=$PRE3"
    echo "GATES=$GATES GOLDEN_EXPECTED=$GOLDEN"
    echo "ACIR_OPS=$ACIR"
    echo "SAMPLED_PEAK_MB_THIS_LEG=${SPEAK:-0}"
  } > "$OUT/${TAG}.r149"
}

# =============== LEG C1A: unblunt lower re-anchor (golden 2,223,114 g; r44/r75) ===============
flip_preset
mlog "PRESET_AFTER: $(grep -E 'for preset:' "$DEF" | tail -1 | tr -d ' ')"
mlog "COMMITTEE_CONFIRM: $(grep -oE 'committee::minimum::(N_PARTIES|T|H)' "$ACT" | sort -u | tr '\n' ' ')"
compile_leg C1A "$CIR"
finalize C1A "$GOLDEN_C1"
restore

# =============== LEG C1B: full perform_range_checks() call NOP (whole-family) ===============
flip_preset
python3 - "$PK" <<'PY'
import sys
p=sys.argv[1]
s=open(p).read()
a='        self.perform_range_checks();'
c=s.count(a)
assert c==1, 'expected exactly 1 perform_range_checks call site; got %d' % c
s=s.replace(a, '// C1B-SHADOW-NOP: self.perform_range_checks();')
assert s.count('C1B-SHADOW-NOP')==1
open(p,'w').write(s)
print('NOP_C1B_OK (PkGeneration::perform_range_checks call commented)')
PY
compile_leg C1B "$CIR"
finalize C1B UNANCHORED-SHADOW-NOP-LEG
restore

# =============== LEG C1C: keep flat eek/sk checks; comment per-limb for-loop only =============
flip_preset
python3 - "$PK" <<'PY'
import sys
p=sys.argv[1]
s=open(p).read()
hd='        for i in 0..L {\n'
i0=s.find(hd)
assert i0!=-1, 'per-limb for-loop header not found'
hdr_end='            );\n        }\n'
e=s.find(hdr_end, i0)
assert e!=-1, 'for-loop tail not found'
end_idx=e+len(hdr_end)
block=s[i0:end_idx]
new='        // C1C-SHADOW-NOP-PER-LIMB-LOOP-BEGIN (r149)\n'
for ln in block.split('\n'):
    new += '        // ' + ln + '\n'
new=new.rstrip('\n')
# bracket accounting: the spliced-out block contains BOTH the `for` header's `{`
# AND its matching close `}` (in hdr_end), so commenting-out preserves file balance.
s2=s[:i0]+new+s[end_idx:]
assert s2.count('C1C-SHADOW-NOP-PER-LIMB-LOOP-BEGIN')==1
# flat-keep invariant: eek + sk checks alive exactly once each
assert s2.count('self.eek.range_check_2bounds')==1
assert s2.count('self.sk.range_check_2bounds')==1
# alive per-limb headers: verify_evaluations keeps its own; the range one must be dead
alive=sum(1 for ln in s2.split('\n') if ln.lstrip().startswith('for i in 0..L {'))
assert alive==1, 'verify_evaluations for-loop must be sole alive occurrence; got %d' % alive
open(p,'w').write(s2)
print('NOP_C1C_OK (per-limb loop commented; eek/sk flat checks + verify_evaluations intact)')
PY
compile_leg C1C "$CIR"
finalize C1C UNANCHORED-SHADOW-NOP-LEG
restore

# =============== tree pin check =================
# conservation guard: in-tree pk_generation.json must be byte-exact vs the pre-round pin
RESTORED_SHA=$(sha256sum "$BIN/target/pk_generation.json" 2>/dev/null | cut -d' ' -f1)
PRE_PIN=$(cat "$OUT/pre_pkgen_json_sha.txt" 2>/dev/null)
PORC=$(git -C "$R" status --porcelain | wc -l)
MPK=$(sha256sum "$PK" | cut -d' ' -f1)
MDEF=$(sha256sum "$DEF" | cut -d' ' -f1)
MACT=$(sha256sum "$ACT" | cut -d' ' -f1)
mlog "PORC_AFTER=$PORC DEF=$MDEF ACT=$MACT PK_SHA=$MPK (expected=$PRE3) PKGEN_PRE=$PRE_PIN RESTORED=$RESTORED_SHA"
{
  echo PORC_AFTER=$PORC
  echo DEF_SHA=$MDEF
  echo ACT_SHA=$MACT
  echo PK_SHA=$MPK
  echo PKGEN_PRE_SHA=$PRE_PIN
  echo PKGEN_RESTORED_SHA=$RESTORED_SHA
  if [ -n "$PRE_PIN" ] && [ "$PRE_PIN" = "$RESTORED_SHA" ]; then echo "CONSERVE_OK"; else echo "CONSERVE_FAIL"; fi
} > "$OUT/restore_check.txt"
if [ "$PORC" != "0" ]; then
  mlog "TREE-DIRTY-BY-RESULTS ($PORC lines); flagged in log entry"
fi
mlog "LEG_DONE"
exit 0