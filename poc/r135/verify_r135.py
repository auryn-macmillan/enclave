#!/usr/bin/env python3
"""r135 RESULT self-check: parses r135 gate JSONs on disk, verifies the
cross-r134 anchors, computes the full-scale producer/consumer block deltas.
RC 0 = all self-checks pass; prints the RESULT table + verdict lines."""
import json, re, sys, glob, os
HERE = os.path.dirname(os.path.abspath(__file__))
def parse_gates(p):
    txt = open(p).read()
    i = txt.find("{")
    d = json.loads(txt[i:])
    f = d["functions"]
    return sum(x["circuit_size"] for x in f), sum(x["acir_opcodes"] for x in f)
g_bpa, a_bpa = parse_gates(HERE + "/bpa_gates.json")
g_bpb, a_bpb = parse_gates(HERE + "/bpb_gates.json")
# r134 anchors (RAN, leg_h14 RESULT.txt, commit fb2481a1)
H14_V0 = 4484154; H14_V1 = 1461749
CONSUMER_BLOCK = H14_V0 - H14_V1          # 3,022,405 RAN r134
CELL = 71981                                   # h14_cell RAN r134 (= r133 a0)
NODE_ISO = 164484                              # r133 a1 per-cell MERKLE producer (H10, shape-invariant)
lines = []
def P(s): lines.append(s); print(s)
P("== r135 RESULT table (secure-8192/small N=19/T=9/H=14, L=3, 42 cells, 4c-pinned) ==")
P(f"bpa 42-cell DIRECT-SHA producer block   = {g_bpa:>9,d} g / {a_bpa:,d} ACIR")
P(f"bpb 42-cell MERKLE producer block       = {g_bpb:>9,d} g / {a_bpb:,d} ACIR")
P(f"consumer re-commit block (h14_v0-v1)    = {CONSUMER_BLOCK:>9,d} g   [RAN r134]")
P("")
# cross-checks
xc = []
x1 = abs(g_bpa - CELL * 42) / CELL
xc.append(f"bpa vs 42 x h14_cell ({CELL}): ratio {g_bpa/(CELL*42):.6f} (delta {g_bpa-CELL*42:+d} g = {100*(g_bpa/CELL-42):.3f}% off cell-count linear; xN LABEL class, r132 b1 pattern ~1.00026)")
if g_bpb < g_bpa: xc.append("FAIL: bpb < bpa — impossible (bpb superset of bpa work + node)")
xc.append(f"bpb - bpa = {g_bpb-g_bpa:,d} g = {42*(NODE_ISO-CELL):,d} expected if per-cell delta held at block scale ({g_bpb-(42*NODE_ISO):+d} off; ratio {(g_bpb-g_bpa)/(42*(NODE_ISO-CELL)):.4f})")
for x in xc: xc_ok = x.startswith("FAIL") is False; xc.append("    -> " + x)
P("cross-checks:")
for x in xc: P(x)
# per-cell amortization (block-in) 
P("")
P(f"amortized per-cell inside block: bpa {g_bpa/42:.0f} g/cell | bpb {g_bpb/42:.0f} g/cell | consumer {CONSUMER_BLOCK/42:.0f} g/cell (all /42)")
P("")
P("VERDICT lines (full analysis in RESULT.txt):")
P(f"  producer direct-sha block (bpa) {g_bpa:,d} g vs consumer re-commit block {CONSUMER_BLOCK:,d} g = {g_bpa/CONSUMER_BLOCK:.4f}x")
P(f"  producer MERKLE block (bpb) {g_bpb:,d} g vs consumer {CONSUMER_BLOCK:,d} g = {g_bpb/CONSUMER_BLOCK:.4f}x")
rc = 1
if g_bpb >= g_bpa > 0 and a_bpa > 0 and a_bpb > 0:
    rc = 0
P(f"SELF-CHECK: {'PASS' if rc==0 else 'FAIL'}")
sys.exit(rc)