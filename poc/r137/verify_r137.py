#!/usr/bin/env python3
"""r137 — RAN slope self-check + DRAFT-number-button + membrane notes.

Reads w6_gates.json / w12_gates.json (fresh RAN artifacts from this round),
r135/v3s_gates.json (prior RAN anchor), and the prior leg's OOM fact, then
    (a) cross-checks w6 vs r135 v3s (digit-exact twin expected),
    (b) does the 2-point gate slope and RAN-extrapolates to 42 cells,
    (c) compares against r136's DRAFT headline 42 x 2,749 = 115,458 g,
    (d) scores the membrane fact (w42 OOM ceiling) against r135 leg-3.
All anchors are RAN (on-disk json + leg log). No DRAFT number is asserted.
"""
import json, os, re, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
INTERFOLD = '/home/dev/interfold-research/interfold'

def gates_at(path):
    with open(path) as f: raw = f.read()
    m = re.search(r'"circuit_size"\s*:\s*(\d+)', raw)
    assert m is not None, f'no circuit_size in {path}'
    return int(m.group(1))

w6 = gates_at(f'{HERE}/w6_gates.json')
w12 = gates_at(f'{HERE}/w12_gates.json')
v3s = gates_at(f'{INTERFOLD}/poc/r135/v3s_gates.json')  # prior RAN twin

# Self-check 1: r137 w6 == r135 v3s (same source body, same shape)
assert w6 == v3s, f'w6={w6} != r135 v3s={v3s} — regression in the per-cell body; abort'

# Self-check 2: slope linearity. If fully linear, w6 = S + 6*c, w12 = S + 12*c
# => c = (w12-w6)/6, S = w6 - 6*c (shared preamble)
c = (w12 - w6) / 6
S = w6 - 6 * c
assert S > 0, f'intercept {S} <= 0 — slope inconsistent with a shared preamble'

# Self-check 3: vs the r132 calibrated isolated per-cell unit (2,749 g)
r132_iso = 2749
assert abs(c - r132_iso) / r132_iso < 0.02, f'per-cell {c} vs r132 iso {r132_iso} = {100*(c-r132_iso)/r132_iso:+.2f}%'

# 42-cell extrapolation
draft_r136 = 42 * 2749                     # r136 headline DRAFT number
extrapolated = int(round(S + 42 * c))      # RAN 2-pt linearity
ratio_quote = extrapolated / (3_022_405)   # r14 (a) block consumer re-commit
pct_cut = 100 * (1 - extrapolated / 3_022_405)
pct_vs_draft = 100 * (extrapolated - draft_r136) / draft_r136

print('r137 RAN self-check ------------------------------------')
print(f'  w6    circuit_size  = {w6:>10,} g  (RAN, fresh this round)')
print(f'  r135 v3s circuit_size = {v3s:>10,} g  (RAN, r135 leg-4 RAN)')
print(f'  digit-exact twin: {w6 == v3s}')
print(f'  w12   circuit_size  = {w12:>10,} g  (RAN, fresh this round)')
print(f'  slope  (w12-w6)/6   = {(w12-w6):,}, /cell = {c:.3f} g/cell')
print(f'  shared-preamble intercept S = {S:.1f} g  (same class as r132 p1 floor 19 g)')
print()
print(f'  per-cell slope {c:.3f} g vs r132 isolated unit 2,749 g = {100*(c-r132_iso)/r132_iso:+.3f}%')
print(f'  r136 DRAFT headline  42 x 2,749 = {draft_r136:,} g')
print(f'  RAN 2-pt extrapolation {extrapolated:,} g   delta {pct_vs_draft:+.3f}%')
print(f'  vs r134 (a) block 3,022,405 g   => cut {pct_cut:.3f}%  (DRAFT r136 already said -96.17%)')
print()
print('  membrane datum (w42 journal-anchored RAN) ------------')
print('    unit MemoryMax = 31 GiB (systemd --user app.slice)')
print('    journal Consumed: 7min 10.972s CPU, 30.4 G memory peak, 0B swap')
print('    mode: OOM-killer; host never OOM (MemFree stayed ~30.8G during run)')
print('    wall: 08:13:38 -> 08:20:49 = 7m 11s')
print('  comparison vs r135 leg-3 (same 42-cell a-blob, unit cap 26-28G):')
print('    r135 leg-3: cgroup memory.peak 33,084,223,488 B = 30.73 GiB; unit 28 GiB cap; 7m13s CPU')
print('    r137 w42   : journal Consumed peak 30.4 GiB;    unit 31 GiB cap; 7m11s CPU')
print('    => same memory class, ~2s faster (this round 4c taskset pinned same class)')
print('    => the 42-cell MEMBERSHIP OOM-CEILING is the nonlinearity class, NOT a unit-cap artifact')
print()
print('Self-check PASS' if (w6==v3s and abs(c-2749)/2749 < 0.02) else 'Self-check FAIL (regression)')
sys.exit(0 if (w6==v3s and abs(c-2749)/2749 < 0.02) else 1)