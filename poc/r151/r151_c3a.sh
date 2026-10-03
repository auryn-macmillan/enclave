#!/usr/bin/env bash
# r151 - C3 re-anchor on new upstream c98b0d1ca (#1999: bound openings/quotients/VK trees).
# SINGLE LEG, measurement-only on a detached origin-tip worktree. Never release.
set -u
export PATH="/usr/local/bin:$HOME/.local/bin:$HOME/.nargo/bin:$PATH"
R=/tmp/r151_origin
OUT=/home/dev/interfold-research/interfold/poc/r151
DEF=$R/circuits/lib/src/configs/default/mod.nr
SE=$R/circuits/lib/src/core/dkg/share_encryption.nr
GOLDEN_PREV=2966353   # C3 golden at old base (r147; base d62e22e)
mlog(){ echo "[$(date -u +%FT%TZ)] $*"; }
cd "$R" || exit 1
cp -f "$DEF" "$OUT/pre_default_mod.nr.bak"
cp -f "$SE"  "$OUT/pre_share_encryption.nr.bak"
PRE=$(sha256sum "$SE" | cut -d' ' -f1)
mlog "PRE_SHA_SE=$PRE HEAD=$(git -C "$R" rev-parse HEAD)"
restore(){ cp -f "$OUT/pre_default_mod.nr.bak" "$DEF"; cp -f "$OUT/pre_share_encryption.nr.bak" "$SE"; mlog RESTORED diff_rc_after=$(diff -q "$OUT/pre_default_mod.nr.bak" "$DEF" >/dev/null && diff -q "$OUT/pre_share_encryption.nr.bak" "$SE" >/dev/null && echo OK || echo BAD); }
trap 'restore; exit 130' TERM INT

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
PY
mlog FLIPPED

cd "$R/circuits/bin/dkg/share_encryption" || { echo CD_FAIL; restore; exit 97; }
rm -f target/share_encryption.json
mlog C3A_COMPILE_START
taskset -c 0-3 /usr/bin/time -v nargo compile --force > "$OUT/C3A_compile_stdout.log" 2> "$OUT/C3A_compile_timev.log"
RC=$?
echo "COMPILE_RC=$RC" >> "$OUT/C3A_compile_timev.log"
mlog "C3A_COMPILE_RC=$RC"
restore; mlog RESTORE_DONE
if [ "$RC" -ne 0 ]; then mlog "LEG FAILED rc=$RC"; exit "$RC"; fi
cp -f target/share_encryption.json "$OUT/C3A_fresh.json"
FRESH=$(sha256sum "$OUT/C3A_fresh.json" | cut -d' ' -f1)
bb gates -b "$OUT/C3A_fresh.json" -t noir-recursive-no-zk > "$OUT/C3A_gates_raw.json" 2> "$OUT/C3A_gates_err.log"
python3 - "$OUT" C3A "$FRESH" "$PRE" "$GOLDEN_PREV" <<'PY'
import json,sys
out,tag,fresh,pre,prev=(sys.argv[1],sys.argv[2],sys.argv[3],sys.argv[4],float(sys.argv[5]))
d=json.load(open(f"{out}/{tag}_gates_raw.json"))
fns=d.get("functions",[])
gates=sum(f.get("circuit_size",0) for f in fns)
acir=sum(f.get("acir_opcodes",0) for f in fns)
wall=0.0; peak=0
for l in open(f"{out}/{tag}_compile_timev.log",errors="replace"):
    if "Elapsed (wall clock) time" in l:
        mm,ss=l.rsplit(":",1); wall=float(mm)*60+float(ss).rstrip()
    if "Maximum resident set size" in l:
        peak=int(l.split()[-1])
delta = gates - prev
open(f"{out}/C3A.r151","w").write(f"""ROUND=r151 LEG=C3A DATE={__import__('datetime').datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')}
COMPILE_RC=0
WALL_TIME={int(wall//60)}:{int(wall%60):02d}.{int(wall%1)*10}
PEAK_RSS_KB={peak} SWAPS=0
FRESH_SHA256={fresh} PRE_SHA_SE={pre}
GATES={int(gates)} PREV_GOLDEN_E3_MIN={int(prev)}
ACIR_OPS={int(acir)}
DELTA_VS_PREV_BASE={int(delta)} DELTA_PCT={delta/prev*100:+.2f}%
""")
print(f"{tag} GATES={gates} ACIR={acir} WALL={wall:.1f}s PEAK_KB={peak} PREV={prev} DELTA={gates-prev} ({delta/prev*100:+.2f}%)")
PY