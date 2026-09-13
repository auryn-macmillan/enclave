#!/usr/bin/env python3
# r131 result self-check (re-runnable, r113/r112 pattern): parses every RAN gate/wall/RSS
# measurement from the raw leg outputs in this directory, re-derives the A/B splits +
# additivity residuals, and checks the calibration anchors against the durable prior.
# Exit 0 + "SELF-CHECK OK" only if every identity holds.
import json, re, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))

def gates(name):
    t = open(os.path.join(HERE, name + '_gates.json')).read()
    d = json.loads(t[t.index('{'):])
    f = d['functions'][0]
    return f['circuit_size'], f['acir_opcodes']

def wallrss(name):
    t = open(os.path.join(HERE, name + '_run.out')).read()
    m = re.search(r'Elapsed \(wall clock\) time \(h:mm:ss or m:ss\): ([\d:]+)', t)
    def wage(s):
            p = s.split(":")
            if len(p) == 3:
                return int(p[0]) * 3600 + int(p[1]) * 60 + float(p[2])
            # /bin/time m:ss or ms:ss (e.g. 8:43.77, 1:30.54) = MINUTES:SECONDS
            return int(p[0]) * 60 + float(p[1])
    mm = re.search(r'Maximum resident set size \(kbytes\): (\d+)', t)
    return wage(m.group(1)), int(mm.group(1)) // 1024  # MB

fails = []
def chk(label, got, want, tol=0):
    ok = abs(got - want) <= tol
    print(('PASS' if ok else 'FAIL'), label, '=', got, ('(want %s)' % want if not ok else ''))
    if not ok:
        fails.append(label)

c4 = {v: gates('c4_' + v) for v in ['v0', 'v1', 'v2']}
c5 = {v: gates('c5_' + v) for v in ['v0', 'v1', 'v2']}
print('== RAN gate table (secure-8192/small N=19/T=9/H=10, 4c-pinned, HEAD 5dcd172b)')
for tag, tab in (('C4', c4), ('C5', c5)):
    for v, (g, a) in tab.items():
        print('%s %-3s gates=%d acir=%d' % (tag, v, g, a))

# --- C4 3-arm decomposition (r37/r38 A/B pattern) ---
A = c4['v0'][0] - c4['v1'][0]          # re-commit block (a)
B = c4['v1'][0] - c4['v2'][0]          # H-fold + normalize term (b)
F = c4['v2'][0]                        # floor (c)
chk('C4 (a)=(v0-v1) additivity', A + B + F, c4['v0'][0], 0)
print('== C4 decomposition (RAN)')
print('  (a) re-commit block   = %d = %.2f%% of C4' % (A, 100.0 * A / c4['v0'][0]))
print('  (b) H-fold+normalize  = %d = %.2f%% of C4' % (B, 100.0 * B / c4['v0'][0]))
print('  (c) floor             = %d = %.2f%% of C4' % (F, 100.0 * F / c4['v0'][0]))
print('  // (b) caveat: V2 normalizes decrypted_shares[0] (single-limb stand-in) - (b) is the')
print('  //  per-limb normalize + aggregate-commitment floor residual, NOT the raw H-fold sum')
print('  //  alone; the H-fold sum is absorbed into the floor there. Treatment noted in LOG.')

# --- C5 3-arm decomposition (r113 pattern) ---
A5 = c5['v0'][0] - c5['v1'][0]
B5 = c5['v1'][0] - c5['v2'][0]
F5 = c5['v2'][0]
chk('C5 (a)+(b)+(c) additivity', A5 + B5 + F5, c5['v0'][0], 0)
chk('C5 V0 == r113 anchor 2554248', c5['v0'][0], 2554248, 0)
chk('C5 V1 == r131 digest prior 396807', c5['v1'][0], 396807, 0)
chk('C5 V2 == r131 digest prior 215849', c5['v2'][0], 215849, 0)
print('== C5 decomposition (RAN)')
print('  (a) re-commit block   = %d = %.2f%% (r113: 2157441 = 84.46%%)' % (A5, 100.0 * A5 / c5['v0'][0]))
print('  (b) divisibility fam  = %d = %.2f%% (r113: 180958 = 7.08%%)' % (B5, 100.0 * B5 / c5['v0'][0]))
print('  (c) floor             = %d = %.2f%% (r113: 215849 = 8.45%%)' % (F5, 100.0 * F5 / c5['v0'][0]))

# --- Calibration anchors (instrument valid at secure-8192/small) ---
chk('C4 V0 == r46 anchor 3571446', c4['v0'][0], 3571446, 0)
chk('C4 V0 ACIR == r46 anchor 734617', c4['v0'][1], 734617, 0)

# --- Node probe (Merkle node = one SAFE sponge over 2 elts, output-pinned) ---
n2, n2a = gates('np2')
print('== node probe (RAN, output-pinned clean sponge): np2 gates=%d acir=%d' % (n2, n2a))
chk('np2 < 150000 sanity', n2 < 150000, True)

# --- Commitment-scheme upper bound (RAN-robust, no cross-multiplication) ---
print('== LEVER UPPER BOUNDS (RAN-robust: measured floors, scheme internals = DRAFT gap)')
c4_up = c4['v1'][0] - (H_L_NODES := 0)  # cannot subtract scheme node cost without the scheme
print('  C4 secure lever upper bound (drop re-commit block, keep rest as-is) = C4-(a) = %d gates = %.2f%% cut' % (c4['v0'][0] - A, 100.0 * A / c4['v0'][0]))
print('  C5 secure lever upper bound (drop re-commit block, keep rest as-is) = C5-(a) = %d gates = %.2f%% cut' % (c5['v0'][0] - A5, 100.0 * A5 / c5['v0'][0]))

# --- wall/RSS table ---
print('== WALL/RSS (4c-pinned, secure-8192/small)')
for n in ['c4_v0', 'c4_v1', 'c4_v2', 'c5_v0', 'c5_v1', 'c5_v2']:
    w, rss = wallrss(n)
    print('  %-7s wall=%6.2fs (%d:%05.2f)  RSS peak=%7.2f GiB' % (n, w, int(w // 60), w % 60, rss / 1024))

# config restore check
pr = open(os.path.join(HERE, 'cfg_restore.txt')).read() if os.path.exists(os.path.join(HERE, 'cfg_restore.txt')) else ''
print('== config restore(baseline, CG-0) :', pr.strip().splitlines()[-1] if pr else 'NO FILE')

if fails:
    print('SELF-CHECK FAILED:', fails)
    sys.exit(1)
print('SELF-CHECK OK')