#!/usr/bin/env bash
# r161 - 2-leg closer: A1 (unblunt on flipped) + X (combined u+e0+e1 solo).
#  DEF keeps flipped carry from prior r161 leg_one.sh runs.
#  Per-leg flow: restore SE -> splice if requested -> compile -> restore SE.
#  usage: r161_leg_tail.sh <a1|x>
set -u
export PATH="$HOME/.local/bin:$HOME/.nargo/bin:/usr/local/bin:$PATH"
[ $# -eq 1 ] || { echo "usage: $0 <a1|x>"; exit 64; }
MODE=$1
case "$MODE" in a1|x) ;; *) echo "bad mode: $MODE"; exit 65; esac
TAG="r161${MODE^^}"
cd /tmp/r161 || exit 96
OUT=/home/dev/interfold-research/interfold/poc/r161
mkdir -p "$OUT"
DEF=/tmp/r161/circuits/lib/src/configs/default/mod.nr
SE=/tmp/r161/circuits/lib/src/core/dkg/share_encryption.nr
DS=/tmp/r161/circuits/bin/dkg
ART=$DS/target/share_encryption.json
PRE_DEF=7f07de82407c9601dd737044af69a068238dd9ff175f51c4d64d8e00980aa207
PRE_SE=308c8c5dd1f7b00a6650bfafd3c5336511964463a64591c7063e5e258f08756e
log(){ echo "[$(date -u +%FT%TZ)] $*"; }
# DEF sanity: must already be flipped (from prior r161 leg_one.sh runs)
python3 - "$DEF" <<'PY' || { log "DEF not ALREADY FLIPPED - abort"; exit 97; }
import sys
a=open(sys.argv[1]).read()
assert 'preset: secure-8192' in a and 'pub use super::secure::dkg;' in a
PY
# SE must be unblunt at entry
if [ "$(sha256sum "$SE" | cut -d' ' -f1)" != "$PRE_SE" ]; then
  log "SE restoring to PRE_SE"
  cp -f "$OUT/zz_share_encryption.nr.bak" "$SE"
fi
restore_SE(){ cp -f "$OUT/zz_share_encryption.nr.bak" "$SE"; }
# Splice
case "$MODE" in
  a1)
    log "MODE=A1 (unblunt - no splice)"
    ;;
  x)
    python3 - "$SE" <<'PY' || { log "SPLICE_FAIL"; exit 98; }
import sys, re
p = sys.argv[1]
s = open(p).read()
orig_open, orig_close = s.count('{'), s.count('}')
for cell in ('u','e0','e1'):
    old = f'        self.{cell}.range_check_2bounds'
    assert s.count(old) == 1, f"expected 1 {cell} call; got {s.count(old)}"
    ls = s.rfind('\n', 0, s.index(old)) + 1
    le = s.find('\n', s.index(old) + len(old))
    line = s[ls:le+1]
    nl = '        // R161-SHADOW-NOP-X-' + cell.upper() + ': ' + line.strip()
    s = s[:ls] + nl + s[le+1:]
    assert s.count('R161-SHADOW-NOP-X-' + cell.upper()) == 1
for cell in ('u','e0','e1'):
    live = re.findall(rf'^\s+self\.{cell}\.range_check_2bounds', s, flags=re.M)
    assert len(live) == 0, f"expected 0 live {cell} after splice"
# Line-comment splices do not touch braces; guard against accidental break.
assert s.count('{') == orig_open and s.count('}') == orig_close, "brace count changed"
open(p, 'w').write(s)
print("SPLICE_X_OK")
PY
    ;;
esac
MV0_KB=$(awk '/^MemAvailable:/{print $2}' /proc/meminfo)
log "MEM_AVAIL_KB_BEFORE_$MODE=$MV0_KB SHA_SE=$(sha256sum "$SE" | cut -c1-8)"
cd "$DS" || exit 96
rm -f "$ART"
S=$(date +%s)
taskset -c 0-3 /usr/bin/time -v nargo compile --force > "$OUT/${TAG}_stdout.log" 2> "$OUT/${TAG}_timev.log"
RC=$?
E=$(date +%s)
echo "$((E-S))s" > "$OUT/${TAG}_wall.raw"
log "COMPILE $TAG rc=$RC wall=$((E-S))s"
cd /tmp/r161 || exit 99
restore_SE
[ $RC -eq 0 ] && [ -s "$ART" ] || { log "$MODE FAIL rc=$RC"; exit 130; }
cp -f "$ART" "$OUT/${TAG}_fresh.json"
bb gates -b "$OUT/${TAG}_fresh.json" -t noir-recursive-no-zk > "$OUT/${TAG}_gates.json" 2> "$OUT/${TAG}_gates_err.log"
python3 - "$OUT" "$TAG" "$MODE" <<'PY'
import json, sys, datetime
out, tag, mode = sys.argv[1:4]
d = json.load(open(out + "/" + tag + "_gates.json"))
g = sum(f.get("circuit_size", 0) for f in d.get("functions", []))
ac = sum(f.get("acir_opcodes", 0) for f in d.get("functions", []))
wall, peak = 0.0, 0
for ln in open(out + "/" + tag + "_timev.log", errors="replace"):
    if "Elapsed (wall clock)" in ln:
        t = ln.split(":", 1)[1].strip().rsplit(" ", 1)[-1]
        try: p = t.split(":"); wall = float(p[0])*60 + float(p[1])
        except Exception: pass
    if "Maximum resident set size" in ln:
        peak = int(ln.split()[-1])
line = f"ROUND=r161 LEG={tag} MODE={mode} BASE=733eb45ae DATE={datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')} GATES={g} ACIR={ac} WALL={wall:.1f}s PEAK_KB={peak}"
open(out + "/" + tag + ".r161", "w").write(line + "\n")
print(line)
PY
log "LEG $MODE OK"
exit 0