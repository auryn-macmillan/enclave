#!/bin/bash
set -u
export PATH="/usr/local/bin:$HOME/.local/bin:$HOME/.nargo/bin:$PATH"
R=/tmp/r151_origin
OUT=/home/dev/interfold-research/interfold/poc/r151
DEF=$R/circuits/lib/src/configs/default/mod.nr
SE=$R/circuits/lib/src/core/dkg/share_encryption.nr
mlog(){ echo "[$(date -u +%FT%TZ)] $*"; }
cd "$R" || exit 1
STEP=$1
if [ "$STEP" = "cleanup" ]; then
  cp -f "$OUT/pre_default_mod.nr.bak" "$DEF"
  cp -f "$OUT/pre_share_encryption.nr.bak" "$SE"
  mlog RESTORED diff=$( { diff -q "$OUT/pre_default_mod.nr.bak" "$DEF" && diff -q "$OUT/pre_share_encryption.nr.bak" "$SE"; } >/dev/null && echo OK || echo BAD)
exit 0
fi
# STEP=leg: ensure preset is flipped, compile, capture
grep -q 'for preset: secure-8192' "$DEF" && mlog PRESET_ALREADY_FLIPPED
python3 - "$DEF" <<'PY'
import sys
p=sys.argv[1]
s=open(p).read()
s=s.replace('for preset: insecure-512','for preset: secure-8192')
s=s.replace('pub use super::insecure::dkg;','pub use super::secure::dkg;')
s=s.replace('pub use super::insecure::threshold;','pub use super::secure::threshold;')
open(p,'w').write(s)
PY
cd "$R/circuits/bin/dkg/share_encryption" || { mlog CD_FAIL; exit 97; }
rm -f target/share_encryption.json
mlog C3A_COMPILE_START "$(date +%s)"
taskset -c 0-3 /usr/bin/time -v nargo compile --force > "$OUT/C3A_compile_stdout.log" 2> "$OUT/C3A_compile_timev.log"
RC=$?
echo "COMPILE_RC=$RC" >> "$OUT/C3A_compile_timev.log"
mlog "C3A_COMPILE_RC=$RC"
cd "$R"
cp -f "$OUT/pre_default_mod.nr.bak" "$DEF"
cp -f "$OUT/pre_share_encryption.nr.bak" "$SE"
mlog RESTORED diff=$( { diff -q "$OUT/pre_default_mod.nr.bak" "$DEF" && diff -q "$OUT/pre_share_encryption.nr.bak" "$SE"; } >/dev/null && echo OK || echo BAD)
if [ "$RC" -ne 0 ]; then mlog LEG_FAILED_RC=$RC; exit "$RC"; fi
cp -f target/share_encryption.json "$OUT/C3A_fresh.json"
FRESH=$(sha256sum "$OUT/C3A_fresh.json" | cut -d' ' -f1)
bb gates -b "$OUT/C3A_fresh.json" -t noir-recursive-no-zk > "$OUT/C3A_gates_raw.json" 2> "$OUT/C3A_gates_err.log"
python3 - "$OUT" C3A "$FRESH" b7106b5ebae5abe74bc8c4c76b0568b3bf0b877fb3f4eefec5cc9a24dfb1da2c 2966353 <<'PY'
import json,sys,datetime
out,tag,fresh,pre,prev=sys.argv[1],sys.argv[2],sys.argv[3],sys.argv[4],float(sys.argv[5])
d=json.load(open(f"{out}/{tag}_gates_raw.json"))
fns=d.get("functions",[])
gates=sum(f.get("circuit_size",0) for f in fns)
acir=sum(f.get("acir_opcodes",0) for f in fns)
wall=0.0; peak=0
for l in open(f"{out}/{tag}_compile_timev.log",errors="replace"):
    if "Elapsed (wall clock) time" in l:
        mm,ss=l.rsplit(":",1); wall=float(mm)*60+float(ss)
    if "Maximum resident set size" in l:
        peak=int(l.split()[-1])
delta=gates-prev
open(f"{out}/C3A.r151","w").write(f"""ROUND=r151 LEG=C3A-OVERRIDE DATE={datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')}
COMPILE_RC=0
WALL_TIME={int(wall//60)}:{int(wall%60):02d}.{int(wall%1)*10}
PEAK_RSS_KB={peak} SWAPS=0
FRESH_SHA256={fresh} PRE_SHA_SE={pre}
GATES={int(gates)} PREV_GOLDEN_E3_MIN={int(prev)}
ACIR_OPS={int(acir)}
DELTA_VS_PREV_BASE={int(delta)} DELTA_PCT={delta/prev*100:+.2f}%
""")
print(f"{tag} GATES={int(gates)} ACIR={int(acir)} WALL={wall:.1f}s PEAK_KB={peak} PREV={int(prev)} DELTA={int(delta)} ({delta/prev*100:+.2f}%)")
PY
mlog LEG_DONE