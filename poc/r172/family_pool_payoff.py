#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
#
# r172 - family-pool PAYOFF MODEL (zero-compile; owner-armed lane (iii),
# DRAFT-ONLY per the owner decision 2026-10-18 ~13:35 EDT: produce the draft
# document + payoff model + exact run command; do NOT run the re-anchor leg).
#
# Every gate number is read from a committed *_gates.json under poc/ (RAN).
# Every structural assumption is printed with a DRAFT tag. Nothing compiled.

import json, os

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(REPO)

def leg(rel):
    d = json.load(open(rel))
    fns = d["functions"]
    return sum(f["circuit_size"] for f in fns), sum(f["acir_opcodes"] for f in fns)

def check(name, got, exp):
    ok = (got == exp)
    print("  [%s] %s: got %d, expect %d, delta %d" % ("OK " if ok else "FAIL", name, got, exp, got - exp))
    if not ok:
        raise SystemExit("IDENTITY FAIL: " + name)

print("== r172 family-pool payoff model (0-compile; RAN inputs from committed JSONs) ==")
print("")

# ---- RAN leaf/split table (re-validated via the same JSONs r171 pins) ----
C1_live = leg("poc/r157/r157A1_live_gates.json")[0]
C1_full = leg("poc/r157/r157B_full_gates.json")[0]
C1_limb = leg("poc/r157/r157C_limb_gates.json")[0]
C2a_live = leg("poc/r158/r158A_live_gates.json")[0]
C2b_live = leg("poc/r163/r163E1_c2b_unblunt_gates.json")[0]
C3_live = leg("poc/r156/C3A_live_gates.json")[0]

fam = {"C1": C1_live - C1_full, "C2a": 552965, "C2b": C2b_live - leg("poc/r163/r163B_full_gates.json")[0], "C3": C3_live - leg("poc/r156/C3B_full_gates.json")[0]}
lim = {"C1": C1_live - C1_limb, "C2a": 552965, "C2b": C2b_live - leg("poc/r163/r163C_limb_gates.json")[0], "C3": C3_live - leg("poc/r156/C3C_limb_gates.json")[0]}
flat = {k: fam[k] - lim[k] for k in fam}

POOL = sum(fam.values())
LIMB_POOL = sum(lim.values())
FLAT_POOL = sum(flat.values())
DKG_TOTAL = 9197169  # r160 golden (cited; C0+C4 residual not re-burned)

check("family pool == 2,849,566 (r160/r171 golden)", POOL, 2849566)
check("per-limb pool == 2,474,008", LIMB_POOL, 2474008)
check("flat pool == 375,558", FLAT_POOL, 375558)
check("C1 family == 1,014,519", fam["C1"], 1014519)
check("C3 family == 729,117", fam["C3"], 729117)
print("")

# ---- r166 measured 3-limb decomposition (the only RAN 3-limb split) ----
B0 = leg("poc/B0_gates.json")[0]
J0 = leg("poc/J0_gates.json")[0]
J1 = leg("poc/J1_gates.json")[0]
J2 = leg("poc/J2_gates.json")[0]
Jall = leg("poc/Jall_gates.json")[0]
cells = [B0 - J0, B0 - J1, B0 - J2]
three_sum = sum(cells)
V1_cell = B0 - Jall
shared_block = V1_cell - three_sum
check("V1 cell == 1,149,657 (r167)", V1_cell, 1149657)
check("3-limb sum == 1,011,237 (r166)", three_sum, 1011237)
check("shared block == 138,420 (r167)", shared_block, 138420)
print("")

# ---- PAYOFF MODEL ----
# Object: the family pool = range-check family mass in the DKG leaves
# (C1 pk_generation + C2a/C2b e_sm range checks + C3 share_encryption bounds).
# Lever class: r115-C6 per-limb AGGREGATE-bound redesign - replace the
# per-limb range-check loops (L = 3 limbs) with ONE aggregate bound.
# Model: payoff(leaf) = per_limb(leaf) - A, where A = irreducible aggregate
# check cost. A is UNMEASURED (DRAFT); scenarios below.
print("== PAYOFF MODEL (per-leaf per-limb mass; payoff = per_limb - A) ==")
print("  per-limb pool      = %d g  (%.2f%% of DKG total %d)" % (LIMB_POOL, 100.0 * LIMB_POOL / DKG_TOTAL, DKG_TOTAL))
print("  flat pool          = %d g  (NOT addressable by an aggregate-bound lever - no per-limb loop)" % FLAT_POOL)
print("  family pool        = %d g  (%.2f%% of total; per-limb + flat)" % (POOL, 100.0 * POOL / DKG_TOTAL))
print("")
print("  SCENARIO 1 [DRAFT] optimistic ceiling A=0: payoff = %d g = %.2f%% of total" % (LIMB_POOL, 100.0 * LIMB_POOL / DKG_TOTAL))
ratio = float(shared_block) / three_sum
cons = int(round(LIMB_POOL * ratio))
print("  CALIBRATION [RAN r166, C2b V1 path]: limb cells %s sum %d; shared block %d" % (cells, three_sum, shared_block))
print("    shared-block ratio = %.4f (13.69%%); per-limb-to-sum ratio = %.4f" % (ratio, 1.0 - ratio))
print("  SCENARIO 2 [DRAFT] calibrated A = ratio x per-limb pool: payoff = %d g = %.2f%% of total" % (LIMB_POOL - cons, 100.0 * (LIMB_POOL - cons) / DKG_TOTAL))
print("  SCENARIO 3 [DRAFT] conservative A = full per-limb pool: payoff = 0 (lever redundant)")
print("")
print("  Per-leaf calibrated payoff [DRAFT scaling, same ratio]:")
for k in ["C1", "C2a", "C2b", "C3"]:
    p = int(round(lim[k] * (1.0 - ratio)))
    print("    %s per-limb %d -> payoff %d g" % (k, lim[k], p))
tp = sum(int(round(lim[k] * (1.0 - ratio))) for k in ["C1", "C2a", "C2b", "C3"])
print("    pool total: %d g = %.2f%% of DKG total" % (tp, 100.0 * tp / DKG_TOTAL))
print("")

# ---- C1 flat decomposition (context: flat is NOT pool-payoff) ----
esm = C1_live - leg("poc/r159/r159B_esm_lifted_solo_gates.json")[0]
eek = C1_live - leg("poc/r170/r170E_eek_solo_gates.json")[0]
sk = C1_live - leg("poc/r170/r170S2c_gates.json")[0]
check("C1 3-solo sum == 200,756", esm + eek + sk, 200756)
check("C1 flat residual == 2,750", flat["C1"] - (esm + eek + sk), 2750)
print("")

# ---- V4-parity cell cross-check (owner quote for lane (i)) ----
V4 = leg("poc/r164/r164V4_c2b_parity_solo_gates.json")[0]
v4_cell = C2b_live - V4
check("V4-parity cell == 208,896 (r164; owner-quoted lane (i) cell)", v4_cell, 208896)
print("")
print("PASS: all RAN identities hold; scenarios above are DRAFT-labeled.")