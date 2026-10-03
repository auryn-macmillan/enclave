#!/usr/bin/env bash
# r147 - C3 aggregate-bound per-limb prototype COST PRICE (DIRECTION 2026-10-02 item (1)).
# r146 RAN-confirmed C3 range family = 1,138,656 g / 38.38% / 9.85% DKG.
# Question: if we replaced the 9 per-limb per-coeff range checks with ONE aggregate
# upper bound per limb (r115 C6-class "chunk bound") we'd pay a small in-circuit
# aggregate-assignment overhead. What is the actual REDUCIBLE?
#
# Legs (measurement only; NEVER release; tree restored byte-exact after each):
#   C3A  unblunt lower C3 re-anchor (golden 2,966,353 g; r39/r41/r75/r84; r145/r146 exact)
#   C3B  share_encryption full check_range_bounds() NOP (reconfirm r146 Delta = -1,138,656 g)
#   C3C  per-limb partial: keep the 4 flat polynomials (u/e0/e1/message),
#        NOP only the per-limb `for` loop body. Isolate the per-limb share of Delta.
#
# Compute budget: 3 legs x (1:30 - 4:00 wall / leg) ~= 9 minutes compute + setup / takeoff
# under 30 - 45 minute soft gate. taskset 0-3, same shape as r145 / r146 on this 8c box.
# Prediction-oriented; never release a NOP-leg artifact.
#
# Reference precedent: r99 / r100 / r145 / r146 shadow-NOP crates form, MemoryMax = 31G
# systemd user unit class on the 8c / 32GiB / 0swap box (r113 / r145 / r146 proven).
# Nargo beta.26 + bb 5.1.0, secure-8192 / minimum committee (N = 3, T = 1, H = 2).
set -u
export PATH="/usr/local/bin:$HOME/.local/bin:$HOME/.nargo/bin:$PATH"
R=/home/dev/interfold-research/interfold
OUT=/home/dev/interfold-research/interfold/poc/r147
BIN=$R/circuits/bin/dkg
CIR="share_encryption"
DEF=$R/circuits/lib/src/configs/default/mod.nr
ACT=$R/circuits/lib/src/configs/committee/active.nr
SE=$R/circuits/lib/src/core/dkg/share_encryption.nr
GOLDEN_C3=2966353
GOLDEN_R146_C3B=1827697   # r146 C3B RAN re-confirmation target
mlog(){ echo "[$(date -u +%FT%TZ)] $*"; }

cd "$R" || exit 1
mkdir -p "$OUT"
mlog "LEG_START nargo=$(nargo --version 2>&1|head -1) bb=$(bb --version 2>&1|head -1) HEAD=$(git -C \"$R\" rev-parse HEAD)"

cp -f "$DEF" "$OUT/pre_default_mod.nr.bak"
cp -f "$ACT" "$OUT/pre_active.nr.bak"
cp -f "$SE"  "$OUT/pre_share_encryption.nr.bak"
PRE3=$(sha256sum "$SE" | cut -d' ' -f1)
mlog "PRE_SHA_SE=$PRE3 PREHEAD=$(git -C "$R" rev-parse HEAD)"

restore(){
  cp -f "$OUT/pre_default_mod.nr.bak" "$DEF"
  cp -f "$OUT/pre_active.nr.bak"     "$ACT"
  cp -f "$OUT/pre_share_encryption.nr.bak" "$SE"
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
  echo PRE_SHA_SE=$PRE3
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

  # commit-swap predictor: the predictor float is non recon at compile done, and the
  # on-disk artifact lives AT BIN/target/. copy it OUT before any restore touches target.
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
    echo "ROUND=r147 LEG=${TAG} DATE=$(date -u +%FT%TZ)"
    echo "COMPILE_RC=$RC"
    echo "PEAK_RSS_KB=$PEAK SWAPS=${SWAP:-0}"
    echo "WALL_TIME=$WALL"
    echo "FRESH_SHA256=$POST PRE_SHA_SE=$PRE3"
    echo "GATES=$GATES GOLDEN_EXPECTED=$GOLDEN"
    echo "ACIR_OPS=$ACIR"
    echo "SAMPLED_PEAK_MB_THIS_LEG=${SPEAK:-0}"
  } > "$OUT/${TAG}.r147"
}

# =============== LEG C3A: lower un-blunt re-anchor (golden 2,966,353) =================
flip_preset
mlog "PRESET_AFTER: $(grep -E 'for preset:' "$DEF" | tail -1 | tr -d ' ')"
mlog "COMMITTEE_CONFIRM: $(grep -oE 'committee::minimum::(N_PARTIES|T|H)' "$ACT" | sort -u | tr '\n' ' ')"
compile_leg C3A "$CIR"
finalize C3A "$GOLDEN_C3"
restore

# =============== LEG C3B: full check_range_bounds() NOP (reconfirm r146 -1,138,656 g) =
flip_preset
python3 - "$SE" <<'PY'
import sys
p=sys.argv[1]; s=open(p).read()
a='        self.check_range_bounds();'
assert s.count(a)==1, 'expected exactly 1 call site in share_encryption.nr; got %d' % s.count(a)
s=s.replace(a, '// C3B-SHADOW-NOP: self.check_range_bounds();')
assert s.count('C3B-SHADOW-NOP')==1
open(p,'w').write(s)
print('NOP_C3B_OK (ShareEncryption::check_range_bounds call commented, recovery r146 C3B)')
PY
compile_leg C3B "$CIR"
finalize C3B "$GOLDEN_R146_C3B"
restore

# =============== LEG C3C: per-limb partial (drop for-loop body only) =================
# Replace the `for i in 0..L { ... }` block's arrow-commit `}` terminator so the body
# executes in place; then delete the loop-def line + `for` bracket line + the matching
# end-brace. Simpler: wrap the entire for-loop in a comment using a sentinel replacement.
flip_preset
python3 - "$SE" <<'PY'
import sys
p=sys.argv[1]
s=open(p).read()
# C3C leg: keep the 4 flat per-coeff range checks (u/e0/e1/message), drop ONLY the
# per-limb `for i in 0..L { ... }` block in `check_range_bounds` (the FIRST occurrence
# = line 303, right after `self.message.range_check_standard`). verify_evaluations
# has a second identical header at ~line 370 which is NOT touched.
anchor_before='        self.message.range_check_standard::<BIT_MSG>(self.configs.msg_bound);\n\n'
hdr='        for i in 0..L {\n'
i0=s.find(anchor_before)
assert i0!=-1, 'message.range_check_standard anchor not found'
hidx=s.find(hdr, i0)
assert hidx!=-1, 'for-loop header not found after message.range_check_standard'
end_anchor='    }\n\n    /// Generates Fiat-Shamir challenge values'
assert s.count(end_anchor)==1, 'for-loop close anchor missing'
eidx=s.find(end_anchor)
assert eidx>hidx
loop_block=s[hidx:eidx]
# comment out every line of the for-loop (header .. matching close brace)
new_block='        // C3C-SHADOW-NOP-PER-LIMB-LOOP-BEGIN (r147)\n'
for ln in loop_block.split('\n'):
    new_block += '        // ' + ln + '\n'
new_block = new_block.rstrip('\n')
s2 = s[:hidx] + new_block + s[eidx:]
assert s2.count('C3C-SHADOW-NOP-PER-LIMB-LOOP-BEGIN')==1
# the two flat-keeping integrity invariants:
assert s2.count('self.u.range_check_2bounds')==1
assert s2.count('self.message.range_check_standard')==1
# Alive-header check: a real `for i in 0..L {` (stripped of its indent) must appear
# exactly once (the verify_evaluations one, which we did NOT touch). Commented-out
# lines start with `//` and do not count as alive headers.
alive_hdrs=sum(1 for ln in s2.split('\n') if ln.lstrip().startswith('for i in 0..L {'))
assert alive_hdrs==1, 'verify_evaluations for-loop must be the sole alive occurrence; got %d alive' % alive_hdrs
open(p,'w').write(s2)
print('NOP_PERLIMB_OK (check_range_bounds for-loop commented; 4 flat + verify_evaluations intact)')
PY
compile_leg C3C "$CIR"
finalize C3C UNANCHORED-SHADOW-NOP-LEG
restore

# =============== tree pin check =================
PORC=$(git -C "$R" status --porcelain | wc -l)
MC3A=$(sha256sum "$SE" | cut -d' ' -f1)
MDEF=$(sha256sum "$DEF" | cut -d' ' -f1)
MACT=$(sha256sum "$ACT" | cut -d' ' -f1)
mlog "PORC_AFTER=$PORC DEF=$MDEF ACT=$MACT SE_SHA=$MC3A (expected=$PRE3)"
{
  echo PORC_AFTER=$PORC
  echo DEF_SHA=$MDEF
  echo ACT_SHA=$MACT
  echo SE_SHA=$MC3A
} > "$OUT/restore_check.txt"
if [ "$PORC" != "0" ]; then
  mlog "TREE-DIRTY-BY-RESULTS ($PORC lines); flagged in log entry"
fi
mlog "LEG_DONE"
exit 0