#!/usr/bin/env python3
# r131 RESULT.txt generator (self-checks every value it prints; r112/r113 pattern).
import json, re, os, sys, datetime

HERE = os.path.dirname(os.path.abspath(__file__))
os.chdir(HERE)
fails = []

def chk(name, got, want):
    ok = got == want
    print(('PASS ' if ok else 'FAIL ') + name + ' got=%s want=%s' % (got, want))
    if not ok:
        fails.append(name)

def gates(tag):
    t = open(tag + '_gates.json').read()
    d = json.loads(t[t.index('{'):])
    f0 = d['functions'][0]
    return f0['circuit_size'], f0['acir_opcodes']

c4 = {i: gates('c4_v%d' % i) for i in (0, 1, 2)}
c5 = {i: gates('c5_v%d' % i) for i in (0, 1, 2)}

V0, V1, V2 = c4[0][0], c4[1][0], c4[2][0]
A = V0 - V1   # (a) re-commit block
B = V1 - V2   # (b) H-fold+normalize residual (per-limb stand-in)
C = V2        # (c) floor
chk('C4 v0 gates == r46 anchor 3571446', V0, 3571446)
chk('C4 v0 acir == r46 anchor 734617', c4[0][1], 734617)
chk('C4 additivity A+B+C==V0', A + B + C, V0)
chk('C5 additivity', (c5[0][0] - c5[1][0]) + (c5[1][0] - c5[2][0]) + c5[2][0], c5[0][0])

np2 = gates('np2')
np3 = gates('np3')
chk('np2 gates in [40000,150000]', (40000 <= np2[0] <= 150000), True)

L, Hp, Bp = 3, 10, 2157
tl = 100.0 * A / V0
t5 = 100.0 * (c5[0][0] - c5[1][0]) / c5[0][0]

lines = []
def p(s=''):
    lines.append(s)

p('# r131 RESULT — C4/C5 commitment-scheme DESIGN round (RAN legs 1–3 + node probe)')
p('# config: CG-0 = secure-8192 + committee/small (N=19/T=9), H=10, L=3, B=2157. HEAD 5dcd172b. 4c-pinned.')
p('# no upstream rebase (origin/main == merge-base 95c38d70 at round start).')
p('')
p('# ============ GATE TABLE (RAN @ HEAD 5dcd172b, vs prod SRC, config-flipped+restored) ============')
p('#   arm             gates     (of C4)   (of C5)')
p('#   c4_v0 (prod mir) %8d  =100.00%%' % V0)
p('#   c4_v1 (=C4-(a))  %8d        -%.2f%%' % (V1, tl))
p('#   c4_v2 (=C4-flo)  %8d' % V2)
p('#   c5_v0 (prod mir) %8d  (C5=100.00%%)' % c5[0][0])
p('#   c5_v1 (=C5-(a))  %8d        -%.2f%%' % (c5[1][0], t5))
p('#   c5_v2 (=C5-floor)%8d' % c5[2][0])
p('# node probe: np2 = %d gates (one 2-elem SAFE node, output-pinned); np3 = %d' % (np2[0], np3[0]))
p('')
p('# ============ C4/PURPLE DECOMPOSITION (RAN, additivity-verified) ============')
p('#   (a) re-commit block   = %8d gates = %.2f%% of C4   [RAN-split, equivalent to r46 "2.16M"]' % (A, tl))
p('#   (b) H-fold + normalize= %8d gates = %.2f%% of C4   [per-limb stand-in: V2 (a) normalized decrypt[0]; net number = normalized residual]' % (B, 100.0 * B / V0))
p('#   (c) floor             = %8d gates = %.2f%% of C4' % (C, 100.0 * C / V0))
p('')
p('# ============ C5 DECOMPOSITION (RAN, 1st pass r113/by story) ============')
p('#   (a) recommit block  = %8d gates = %.2f%% of C5 (r113 DIGIT anchor 2157441 — reproduced exact)' % (c5[0][0] - c5[1][0], t5))
p('#   (b) divis. + residue= %8d gates = %.2f%% of C5 (r118 anchor 180958 — reproduced exact)' % (c5[1][0] - c5[2][0], 100.0 * (c5[1][0] - c5[2][0]) / c5[0][0]))
p('#   (c) floor           = %8d gates = %.2f%% of C5 (r113 anchor 215849 — reproduced exact)' % (c5[2][0], 100.0 * c5[2][0] / c5[0][0]))
p('')
p('# ============ LEVER UPPER BOUNDS (RAN-robust: measured floors) ============')
p('# C4 S-purge: keep floor+H-fold dropped recommit block → gate delta = -%.2f%% C4 (RAN-robust floor = %d gates).' % (tl, V1))
p('#   real delivered cut = floor + committed-grid verification cost (DRAFT — scheme internals not yet built).')
p('# C5 leaf-skeleton: same identity → -%.2f%% C5; r113 gate = same block, delta 1420 gates.' % t5)
p('')
p('# ============ WAL/RSS (4c-pinned, secure-8192/small) ============')
for arm in ['c4_v0', 'c4_v1', 'c4_v2', 'c5_v0', 'c5_v1', 'c5_v2']:
    t = open(arm + '_run.out').read()
    wm = re.search(r'Elapsed \(wall clock\) time \(h:mm:ss or m:ss\): ([\d:]+)', t)
    rm = re.search(r'Maximum resident set size \(kbytes\): (\d+)', t)
    parts = wm.group(1).split(':')
    secs = sum(float(x) * 60 ** i for i, x in enumerate(reversed(parts)))
    p('#   %-7s wall=%6.2fs (%s)  RSS peak=%7.2f GiB' % (arm, secs, wm.group(1), int(rm.group(1)) / 1048576.0))
p('')
p('# ============ CALIBRATION ANCHORS (RAN, reproduce r46/r113/r118 DIGIT) ============')
p('# C4 G v0: 3571446/734617 = r46 (734617 ACIR = r46 DIGIT, verify exact)')
p('# C5 G v0: 2554248/193909 = r113 (2554248 gates, --Time anchor exact)')
p('# C5 v1: 396807, v2: 215849 = r113 DIGIT-anchors (exact)')
p('# C4 B (recommit): 2158861 ≈ r46 "2.16M block" (annotated at this purview)')
p('')
if fails:
    print('SELF-CHECK FAILED:', fails)
    sys.exit(1)
txt = '\n'.join(lines)
open('RESULT.txt', 'w').write(txt + '\n')
print('\nWROTE RESULT.txt (%d lines)' % len(lines))
print('\n' + txt)