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
PORC=$(git -C "$R" status --porcelain | wc -l)
MPK=$(sha256sum "$PK" | cut -d' ' -f1)
MDEF=$(sha256sum "$DEF" | cut -d' ' -f1)
MACT=$(sha256sum "$ACT" | cut -d' ' -f1)
mlog "PORC_AFTER=$PORC DEF=$MDEF ACT=$MACT PK_SHA=$MPK (expected=$PRE3)"
{
  echo PORC_AFTER=$PORC
  echo DEF_SHA=$MDEF
  echo ACT_SHA=$MACT
  echo PK_SHA=$MPK
} > "$OUT/restore_check.txt"
if [ "$PORC" != "0" ]; then
  mlog "TREE-DIRTY-BY-RESULTS ($PORC lines); flagged in log entry"
fi
mlog "LEG_DONE"
exit 0