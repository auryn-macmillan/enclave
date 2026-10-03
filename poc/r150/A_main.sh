#!/usr/bin/env bash
# r150 - C4 range-family absence proof (DIRECTION 2026-10-02, r149 NEXT = "r150 C4 range-family shadow-NOP";
# premise source-audit discovered C4 has NO range-check call sites so the B+C legs are vacuous and this
# round upgrades to: RAN unblunt C4A re-anchor + RAN source-span audit = kill-round).
#
# Working branch: i5/dkg-research @ 936d357f6 (r149 tip), base origin/main d62e22e16 UNMOVED (REBASE no-op;
# merge-base == origin/main == HEAD base; 92 ahead / 0 behind). Box 8c / ~31.5 GiB avail / 0 swap / 0 IOPS
# reset (btime new per 2026-09-11 re-provision).
#
# Leg (measurement only; NEVER release; tree restore per-leg byte-exact, r99/r100/r145/r146/r147/r149 form):
#   C4A  unblunt lower C4 re-anchor (golden 1,746,030 g; r45/r46/r48/r75/r101 byte-exact pinned)
#        secure-8192/minimum (N=3/T=1/H=2, pure-CRT). ONLY leg -- C4B/C4C would need a range-NOP anchor
#        that the source did not yield (0 range_check_* in the C4 leaf cone; see source-audit in poc/r150/).
#
# Prediction: 1 leg wall ~3:00-3:10 (golden r75 3:05.38 wall / r101 2:37.80 @4c; era drift ~0.99993x RAN r101)
# Compute ceiling 15 min. NOT a sound vehicle - measurement only. Recover byte-exact after each leg.
set -u
export PATH="/usr/local/bin:$HOME/.local/bin:$HOME/.nargo/bin:$PATH"
R=/home/dev/interfold-research/interfold
OUT=$R/poc/r150
BIN=$R/circuits/bin/dkg
CIR="share_decryption"
DEF=$R/circuits/lib/src/configs/default/mod.nr
ACT=$R/circuits/lib/src/configs/committee/active.nr
SD=$R/circuits/lib/src/core/dkg/share_decryption.nr
GOLDEN_C4=1746030
mlog(){ echo "[$(date -u +%FT%TZ)] $*"; }

cd "$R" || exit 1
mkdir -p "$OUT"
mlog "LEG_START nargo=$(nargo --version 2>&1|head -1) bb=$(bb --version 2>&1|head -1) HEAD=$(git -C "$R" rev-parse HEAD)"

cp -f "$DEF" "$OUT/pre_default_mod.nr.bak"
cp -f "$ACT" "$OUT/pre_active.nr.bak"
cp -f "$SD"  "$OUT/pre_share_decryption.nr.bak"
(mkdir -p "$OUT/target_snap" && tar -cf "$OUT/target_snap/dkg_target_pre.tar" -C "$BIN" target) 2>/dev/null
sha256sum "$BIN/target/share_decryption.json" 2>/dev/null | cut -d' ' -f1 > "$OUT/pre_sdec_json_sha.txt"
PRE3=$(sha256sum "$SD" | cut -d' ' -f1)
mlog "PRE_SHA_SD=$PRE3 PREHEAD=$(git -C "$R" rev-parse HEAD)"

restore(){
  cp -f "$OUT/pre_default_mod.nr.bak" "$DEF"
  cp -f "$OUT/pre_active.nr.bak"     "$ACT"
  cp -f "$OUT/pre_share_decryption.nr.bak" "$SD"
  rm -rf "$BIN/target" && (cd "$BIN" && tar -xf "$OUT/target_snap/dkg_target_pre.tar")
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
  echo PRE_SHA_SD=$PRE3
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
  if [ "$GATES" != "$GOLDEN" ]; then
    mlog "${TAG}_GATES_VS_GOLDEN gates=$GATES golden=$GOLDEN"
  fi
  {
    echo "ROUND=r150 LEG=${TAG} DATE=$(date -u +%FT%TZ)"
    echo "COMPILE_RC=$RC"
    echo "PEAK_RSS_KB=$PEAK SWAPS=${SWAP:-0}"
    echo "WALL_TIME=$WALL"
    echo "FRESH_SHA256=$POST PRE_SHA_SD=$PRE3"
    echo "GATES=$GATES GOLDEN_EXPECTED=$GOLDEN"
    echo "ACIR_OPS=$ACIR"
    echo "SAMPLED_PEAK_MB_THIS_LEG=${SPEAK:-0}"
  } > "$OUT/${TAG}.r150"
}

# =============== LEG C4A: unblunt lower re-anchor (golden 1,746,030 g; r45/r46/r48/r75/r101) ===============
flip_preset
mlog "PRESET_AFTER: $(grep -E 'for preset:' "$DEF" | tail -1 | tr -d ' ')"
mlog "COMMITTEE_CONFIRM: $(grep -oE 'committee::minimum::(N_PARTIES|T|H)' "$ACT" | sort -u | tr '\n' ' ')"
compile_leg C4A "$CIR"
finalize C4A "$GOLDEN_C4"
restore

# conservation guard + tree pin
RESTORED_SHA=$(sha256sum "$BIN/target/share_decryption.json" 2>/dev/null | cut -d' ' -f1)
PRE_PIN=$(cat "$OUT/pre_sdec_json_sha.txt" 2>/dev/null)
PORC=$(git -C "$R" status --porcelain | wc -l)
MSD=$(sha256sum "$SD" | cut -d' ' -f1)
MDEF=$(sha256sum "$DEF" | cut -d' ' -f1)
MACT=$(sha256sum "$ACT" | cut -d' ' -f1)
mlog "PORC_AFTER=$PORC DEF=$MDEF ACT=$MACT SD_SHA=$MSD (expected=$PRE3) SDEC_PRE=$PRE_PIN RESTORED=$RESTORED_SHA"
{
  echo PORC_AFTER=$PORC
  echo DEF_SHA=$MDEF
  echo ACT_SHA=$MACT
  echo SD_SHA=$MSD
  echo SDEC_PRE_SHA=$PRE_PIN
  echo SDEC_RESTORED_SHA=$RESTORED_SHA
  if [ -n "$PRE_PIN" ] && [ "$PRE_PIN" = "$RESTORED_SHA" ]; then echo "CONSERVE_OK"; else echo "CONSERVE_FAIL"; fi
} > "$OUT/restore_check.txt"

if [ "$PORC" != "0" ]; then
  mlog "TREE-DIRTY-BY-RESULTS ($PORC lines); flagged in log entry"
fi
mlog "LEG_DONE"
exit 0