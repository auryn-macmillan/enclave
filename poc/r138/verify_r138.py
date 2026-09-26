#!/usr/bin/env python3
"""r138 -- RAN-anchor the r136 in-leaf WALL ceiling via r134 leg_h14 in-leg numbers.

Self-sourcing: every wall/peak/gate below is READ from the prior-round on-disk
artifacts, not hardcoded. Round constants are used only as self-checks that the
re-read matches history (regression canary). No fresh compile this round.

The decisive methodological point (skill rule #4: keep the RAN parts robust to
the DRAFT parts): r136 printed  "1,577,207 g = -64.83% in-leaf wall class
reduction".  That is a GATE ratio (gate_postswap / gate_V0) relabeled as a wall
claim.  r138 separates the two quantities with RAN inputs on both endpoints:

  gate: (a)-block is 67.40% of V0 gates   -> re-add binding row -> post-swap gate
  wall: (a)-block is 94.25% of V0 wall    -> the S-sponge block is memory-
        bandwidth-BROKEN (r131/r132), so dropping it recovers FAR more wall
        than its gate share suggests.

RAN inputs (all on disk):
  r134 leg_h14 : V0 / V1 / h14_cell / h14_grid   (gate + wall + peak)
  r137 w6/w12  : per-cell running-acc gate slope (in-block 114,761 g @ 42 cells)
DRAFT (flagged, NOT a measurement):
  the per-cell running-acc 42-cell ROW wall (single-blob OOM'd r137 w42; the
  per-cell instantiation form was never wall-compiled) -> a band, not a fact.
"""
import json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
LEG = '/home/dev/interfold-research/interfold/poc/r133/leg_h14'
R137 = '/home/dev/interfold-research/interfold/poc/r137'

def run_wall_peak(path):
    """Parse a `time -v`-style run out: Elapsed wall (seconds) + max RSS (GiB)."""
    with open(path) as f:
        txt = f.read()
    m = re.search(r'Elapsed \(wall clock\) time .*?:\s*([\d:]+(?:\.\d+)?)', txt)
    assert m, f'no Elapsed wall in {path}'
    parts = m.group(1).split(':')
    s = float(parts[-2]) * 60 + float(parts[-1]) if len(parts) >= 2 else float(parts[-1])
    r = re.search(r'Maximum resident set size \(kbytes\):\s*(\d+)', txt)
    assert r, f'no max RSS in {path}'
    rss_kib = int(r.group(1))
    return s, rss_kib / (1024 * 1024)  # GiB (kib -> GiB)

def gates(path):
    with open(path) as f:
        raw = f.read()
    m = re.search(r'"circuit_size"\s*:\s*(\d+)', raw)
    assert m, f'no circuit_size in {path}'
    return int(m.group(1))

# ---- RAN inputs, read from disk ----
v0_gate = gates(f'{LEG}/h14_v0_gates.json')
v1_gate = gates(f'{LEG}/h14_v1_gates.json')
cell_gate = gates(f'{LEG}/h14_cell_gates.json')
grid_gate = gates(f'{LEG}/h14_grid_gates.json')

v0_wall, v0_pk = run_wall_peak(f'{LEG}/h14_v0_run.out')
v1_wall, v1_pk = run_wall_peak(f'{LEG}/h14_v1_run.out')
cell_wall, cell_pk = run_wall_peak(f'{LEG}/h14_cell_run.out')
grid_wall, grid_pk = run_wall_peak(f'{LEG}/h14_grid_run.out')

w6_gate = gates(f'{R137}/w6_gates.json')
w12_gate = gates(f'{R137}/w12_gates.json')

# ---- round-constant regression canaries (die if the disk moved from r134/r137) ----
assert v0_gate == 4_484_154,  f'r134 V0 gate {v0_gate} != 4,484,154 (artifact moved?)'
assert v1_gate == 1_461_749,  f'r134 V1 gate {v1_gate} != 1,461,749 (artifact moved?)'
assert cell_gate == 71_981,   f'r134 cell gate {cell_gate} != 71,981'
assert grid_gate == 3_169,    f'r134 grid gate {grid_gate} != 3,169'
assert w6_gate == 16_409 and w12_gate == 32_801, 'r137 w6/w12 gate canary failed'

# ---- (a)-block = V0 - V1 (RAN subtraction) ----
a_gate = v0_gate - v1_gate                 # 3,022,405
a_wall = v0_wall - v1_wall                 # (a) S-sponge wall, RAN
a_pk   = v0_pk  - v1_pk
a_pct_gate = 100 * a_gate / v0_gate        # 67.40%
a_pct_wall = 100 * a_wall / v0_wall        # 94.25% (memory-bandwidth-bound)
assert abs(a_gate - 3_022_405) < 2, f'(a) gate {a_gate} off r134 anchor by >2'

# ---- in-block consumer binding, RAN 2-pt slope (r137) ----
c = (w12_gate - w6_gate) / 6
S = w6_gate - 6 * c
runacc_42 = int(round(S + 42 * c))         # 114,761 (RAN)
r136_draft_block = 42 * 2749                # r136 DRAFT headline used 2,749 iso x42
assert runacc_42 == 114_761, f'r137 in-block 42-cell {runacc_42} != 114,761'

# ---- post-swap in-leaf, GATE (RAN: V1 + runacc; grid-row floor as RAN bound) ----
post_gate_runacc = v1_gate + runacc_42     # RAN
post_gate_grid   = v1_gate + grid_gate     # RAN floor (2-felt compact row)
post_wall_grid   = v1_wall + grid_wall     # RAN floor (both endpoints RAN)
r136_draft_gate  = 1_577_207
gate_cut_vs_v0   = 100 * (1 - post_gate_runacc / v0_gate)
gate_delta_vs_draft = 100 * (post_gate_runacc - r136_draft_gate) / r136_draft_gate
wall_cut_grid    = 100 * (1 - post_wall_grid / v0_wall)

print('r138 RAN in-leaf wall anchor -------------------------------------------')
print(f'  r134 V0   (full C4, (a) present)   gate {v0_gate:>9,}  wall {v0_wall:7.2f}s  peak {v0_pk:6.2f} GiB')
print(f'  r134 V1   ((a) dropped)            gate {v1_gate:>9,}  wall {v1_wall:7.2f}s  peak {v1_pk:6.2f} GiB')
print(f'  r134 cell (1x direct-sha p4)       gate {cell_gate:>9,}  wall {cell_wall:6.2f}s  peak {cell_pk:6.2f} GiB')
print(f'  r134 grid (42x compact 2-felt row) gate {grid_gate:>9,}  wall {grid_wall:6.2f}s  peak {grid_pk:6.2f} GiB')
print()
print('  (a)-block (V0 - V1) [RAN]')
print(f'    gate {a_gate:>9,}  = {a_pct_gate:5.2f}% of V0 gate')
print(f'    wall {a_wall:>9.2f}s = {a_pct_wall:5.2f}% of V0 wall   <-- the (a) S-sponge is memory-')
print(f'    peak {a_pk:>9.2f} GiB                          bandwidth-bound, not gate-bound (r131/r132)')
print()
print('  in-block consumer binding, r137 2-pt slope [RAN]')
print(f'    c = (w12-w6)/6 = {c:.3f} g/cell ; S = {S:.1f} g')
print(f'    42-cell in-block = {runacc_42:,} g  (r136 DRAFT block = 42x2749 = {r136_draft_block:,} g)')
print()
print('  POST-SWAP in-leaf [gate RAN; wall RAN-floor + DRAFT band]')
print(f'    GATE  runacc-binding : V1 + {runacc_42:,} = {post_gate_runacc:,} g')
print(f'            -> gate cut vs V0 = {gate_cut_vs_v0:.2f}%   (r136 DRAFT said { 100*(1-r136_draft_gate/v0_gate):.2f}%)')
print(f'            -> vs r136 DRAFT 1,577,207 g = {gate_delta_vs_draft:+.3f}%  (r138 RAN refines to {post_gate_runacc:,})')
print(f'    GATE  grid-row floor : V1 + {grid_gate:,} = {post_gate_grid:,} g  (cheapest binding class)')
print(f'    WALL  RAN floor      : V1 {v1_wall:.2f}s + grid row {grid_wall:.2f}s = {post_wall_grid:.2f}s')
print(f'            -> WALL cut vs V0 {v0_wall:.2f}s = {wall_cut_grid:.2f}%')
print(f'    WALL  runacc-binding : V1 + [42-cell running-acc row wall]')
print(f'            -> DRAFT (single-blob 42-cell OOM-d r137 w42 @30.4G; per-cell wall form not')
print(f'               separately wall-compiled) -- a band above the {post_wall_grid:.2f}s RAN floor,')
print(f'               NOT a measured number.')
print()
print('  KEY RECONCILIATION (r136 -> r138):')
print(f'    r136 "1,577,207 g = -64.83% in-leaf wall" was a GATE ratio mislabeled as wall.')
print(f'    r138: GATE post-swap = {post_gate_runacc:,} g = -{gate_cut_vs_v0:.2f}% of V0 gate (RAN; r136 -64.83% confirmed).')
print(f'           WALL  post-swap FLOOR (grid-row binding) = {post_wall_grid:.2f}s = -{wall_cut_grid:.2f}% of V0 wall (RAN).')
print(f'    The (a) S-sponge block is -{a_pct_wall:.2f}% of the in-leaf WALL but only -{a_pct_gate:.2f}% of its')
print(f'    GATES, because it is memory-bandwidth-bound. The wall win dwarfs the gate win.')
print(f'    Peak: V0 {v0_pk:.2f} -> V1 {v1_pk:.2f} GiB = -{100*(1-v1_pk/v0_pk):.1f}% (RAN) -- this is the class that')
print(f'    unbounded secure-8192/small C4 on this 32 GiB box (r131/r136).')
print()
print('Self-check PASS' if (v0_gate==4_484_154 and runacc_42==114_761 and a_gate==3_022_405) else 'Self-check FAIL')
sys.exit(0 if (v0_gate==4_484_154 and runacc_42==114_761 and a_gate==3_022_405) else 1)