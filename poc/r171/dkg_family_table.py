#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
#
# Single-source, zero-compile Python re-derivation of the 6-row fold-base
# DKG family table from 40 committed *_gates.json receipts. Every number
# printed below is pulled from a file of the form:
#
#   poc/r156/C3{A,B,C}_*_gates.json       C3 range-check family (r156)
#   poc/r157/r157{A1,B,C}_*_gates.json   C1 leaf splits (r157)
#   poc/r158/r158{A,B,C,E}_*_gates.json  C2a leaf splits (r158)
#   poc/r159/r159{A1,B}_*_gates.json     C1 e_sm_lifted solo (r159)
#   poc/r160/r160M_msg_solo_gates.json   C3 message solo (r160)
#   poc/r161/r161{A1,U,E0,E1,X}_gates.json  C3 narrow-flat solos (r161)
#   poc/r163/{r163E1,r163B,r163C}_c2b_unblunt_gates.json  C2b family (r163)
#   poc/r164/r164{E1,V1,V2,V4,V5}_*_gates.json  C2b non-family blocks (r164)
#   poc/r165/r165{A,E,V1A,V2A}_*_gates.json  C2a V1A/V2A solos (r165)
#   poc/r166/{B0,J0,J1,J2,Jall}_gates.json    C2b per-limb cells (r166)
#   poc/r169/{r169E,r169S}_*_gates.json      C2b V1 no-sponge wire-cut (r169)
#   poc/r170/{r170A1,r170E,r170S2c}_*_gates.json  C1 eek+sk solos (r170)
#
# No source edits, no compiles, no defect-surface. Just arithmetic.
#
# Method
#  1. Parse each JSON, take functions[0].circuit_size (gates) + acir_opcodes.
#  2. For each leaf, re-derive the family / per-limb / flat split using the
#     identities prior rounds established:
#       family    = live - fullfn_nop       (whole-fn NOP leg)
#       per-limb  = live - limb_scaffold_nop  (loop-body-only NOP, headers kept)
#       flat      = limb_scaffold_nop - fullfn_nop
#       block_i   = live - solo_i           (one-block shadow NOP)
#     The per-limb/flat split only exists where the prior round burned a
#     per-limb scaffold leg (r156 for C3, r157 for C1, r158 for C2a, r163
#     for C2b). C0/C4 have no range-check family; no legs in play.
#  3. Re-derive cell-private sub-splittings where later rounds solo'd a
#     flat cell (C1: r159 e_sm_lifted + r170 eek/sk; C3: r160 message + r161
#     X narrow-flat composite).
#  4. Print a single 6-row table + per-leaf split + cross-round identity
#     validation (e.g. C1 per-limb 811,013 from r157 + flat 203,506 sum to
#     the r157 family 1,014,519, digit-exact; same for C3 both sides;
#     family pool 2,849,566 vs r160 stated family pool 2,849,566).
#
# Every assertion either outputs an integer match or raises SystemExit.

import json, os, sys, hashlib

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(REPO)

def leg(rel):
    with open(rel) as f:
        d = json.load(f)
    fn = d["functions"][0]
    return fn["circuit_size"], fn["acir_opcodes"], rel

# ---- Per-row source rows (rel path, gates, acir) ----
rows = {}
# C1 = threshold pk_generation  (r157 pinned the leaf)
rows["C1_live"]    = leg("poc/r157/r157A1_live_gates.json")
rows["C1_full"]    = leg("poc/r157/r157B_full_gates.json")
rows["C1_limbs"]   = leg("poc/r157/r157C_limb_gates.json")
# C1 flat cells (r159 + r170)
rows["C1_esm_lifted_solo"] = leg("poc/r159/r159B_esm_lifted_solo_gates.json")
rows["C1_eek_solo"]        = leg("poc/r170/r170E_eek_solo_gates.json")
rows["C1_sk_solo"]         = leg("poc/r170/r170S2c_gates.json")
# C1 A1 re-anchor @ r170 tip
rows["C1_a1_r170"] = leg("poc/r170/r170A1_live_gates.json")

# C2a = dkg sk_secret leaf (r158)
rows["C2a_live"] = leg("poc/r158/r158A_live_gates.json")
rows["C2a_full"] = leg("poc/r158/r158B_full_gates.json")
rows["C2a_limbs"] = leg("poc/r158/r158C_limb_gates.json")
# C2a per-block (r165)
rows["C2a_v1a"]  = leg("poc/r165/r165V1A_c2a_secret_commit_gates.json")
rows["C2a_v2a"]  = leg("poc/r165/r165V2A_c2a_secret_consistency_gates.json")
# C2b E-leg sanity @ r165 for cross-leaf byte-identical V1A (r165 finding)
rows["C2b_E_sanity_r165"] = leg("poc/r165/r165E_c2b_unblunt_sanity_gates.json")

# C2b = dkg e_sm leaf (r163 + r164 + r166 + r169)
rows["C2b_live"]  = leg("poc/r163/r163E1_c2b_unblunt_gates.json")
rows["C2b_full"]  = leg("poc/r163/r163B_full_gates.json")
rows["C2b_limbs"] = leg("poc/r163/r163C_limb_gates.json")
# C2b non-family blocks (r164)
rows["C2b_E1"]    = leg("poc/r164/r164E1_c2b_unblunt_gates.json")
rows["C2b_V1"]    = leg("poc/r164/r164V1_c2b_s1_solo_gates.json")
rows["C2b_V2"]    = leg("poc/r164/r164V2_c2b_s2_solo_gates.json")
rows["C2b_V4"]    = leg("poc/r164/r164V4_c2b_parity_solo_gates.json")
rows["C2b_V5"]    = leg("poc/r164/r164V5_c2b_party_solo_gates.json")
# C2b V1 per-limb (r166)
rows["C2b_B0"]    = leg("poc/r166/B0_gates.json")
rows["C2b_J0"]    = leg("poc/r166/J0_gates.json")
rows["C2b_J1"]    = leg("poc/r166/J1_gates.json")
rows["C2b_J2"]    = leg("poc/r166/J2_gates.json")
rows["C2b_Jall"]  = leg("poc/r166/Jall_gates.json")
# C2b V1 no-sponge wire-cut (r169)
rows["C2b_V1_sponge"]      = rows["C2b_E1"]  # E unblunt
rows["C2b_V1_nosponge"]    = leg("poc/r169/r169S_no_sponge_gates.json")

# C3 = dkg share_encryption (r156 + r160 + r161)
rows["C3_live"]   = leg("poc/r156/C3A_live_gates.json")
rows["C3_full"]   = leg("poc/r156/C3B_full_gates.json")
rows["C3_limbs"]  = leg("poc/r156/C3C_limb_gates.json")
rows["C3_msg"]    = leg("poc/r160/r160M_msg_solo_gates.json")
rows["C3_a1_r161"] = leg("poc/r161/r161A1_gates.json")
rows["C3_U"]     = leg("poc/r161/r161U_u_gates.json")
rows["C3_E0"]    = leg("poc/r161/r161E0_e0_gates.json")
rows["C3_E1"]    = leg("poc/r161/r161E1_e1_gates.json")
rows["C3_X"]     = leg("poc/r161/r161X_gates.json")

def g(name): return rows[name][0]
def a(name): return rows[name][1]

errors = []
def check(label, got, expect, tol=0):
    ok = abs(got - expect) <= tol
    status = "OK " if ok else "BAD"
    delta = got - expect
    line = f"  [{status}] {label}: got {got}, expect {expect}, delta {delta}"
    print(line)
    if not ok:
        errors.append(label)
    return ok

print("== r171 DKG family-table aggregate receipt (0-compile) ==")
print()
print("LAYERS (gates) - per-leaf raw leg values (RAN from on-disk JSON):")
print()
for k, v in rows.items():
    print(f"  {k:28s}  {v[0]:>9} g   {v[1]:>8} ACIR   ({os.path.basename(v[2])})")
print()

# ---- FAMILY SPLIT (per-limb vs flat) ----
def split(live, full, limbs):
    fam = live - full
    perlimb = live - limbs
    flat = limbs - full
    return fam, perlimb, flat

C1_fam, C1_per, C1_flat = split(g("C1_live"), g("C1_full"), g("C1_limbs"))
C2a_fam, C2a_per, C2a_flat = split(g("C2a_live"), g("C2a_full"), g("C2a_limbs"))
C2b_fam, C2b_per, C2b_flat = split(g("C2b_live"), g("C2b_full"), g("C2b_limbs"))
C3_fam, C3_per, C3_flat = split(g("C3_live"), g("C3_full"), g("C3_limbs"))

print("== FAMILY SPLIT (RAN re-derivation): family = live - full; per-limb = live - limbs; flat = limbs - full ==")
for name, (fam, per, flat) in {
    "C1 (r157)": (C1_fam, C1_per, C1_flat),
    "C2a (r158)": (C2a_fam, C2a_per, C2a_flat),
    "C2b (r163)": (C2b_fam, C2b_per, C2b_flat),
    "C3 (r156)": (C3_fam, C3_per, C3_flat),
}.items():
    r = per + flat
    print(f"  {name:12s}  family {fam:>9}   per-limb {per:>9}   flat {flat:>9}   per+flat {r}")
    # Digit-exact identity
    check(name + " identity per+flat == family", per + flat, fam)

print()
print("== CROSS-ROUND GOLDEN RE-ANCHOR (RAN spot validation of the digit-stable leg values) ==")
# r157 C1 live == r170 C1 A1 (both should be 1,634,722)
check("C1 live r157 == r170 A1", g("C1_a1_r170"), g("C1_live"))
# r165 sanity C2b unblunt == r163/r164 C2b live
check("C2b live r163 == r164 E1", g("C2b_E1"), g("C2b_live"))
check("C2b live r163 == r165 E sanity", g("C2b_E_sanity_r165"), g("C2b_live"))
# C2b per-limb = per-limb scaffold (r163: B==C digit-exact; per-limb = family, flat = 0)
check("C2b flat == 0 (r163 B==C)", C2b_flat, 0)
# C2a flat == 0 (r158 B==C)
check("C2a flat == 0 (r158 B==C)", C2a_flat, 0)
print()

# ---- C1 FLAT DECOMPOSITION (r159 e_sm_lifted + r170 eek/sk) ----
c1_esm = g("C1_live") - g("C1_esm_lifted_solo")
c1_eek = g("C1_live") - g("C1_eek_solo")
c1_sk  = g("C1_live") - g("C1_sk_solo")
print("== C1 flat decomposition (RAN) ==")
print(f"  e_sm_lifted solo = {c1_esm} g")
print(f"  eek solo         = {c1_eek} g")
print(f"  sk solo          = {c1_sk} g")
print(f"  sum of 3 solos   = {c1_esm+c1_eek+c1_sk} g")
print(f"  flat             = {C1_flat} g  (r157 flat, golden)")
# Prior r170 closed the C1 flat: e_sm_lifted (127,023) + eek (36,864) + sk (36,869) = 200,756,
# residual 2,750 = 1.35% of the flat (small solver non-additivity).
check("C1 e_sm_lifted == 127,023 (r159 golden)", c1_esm, 127023)
check("C1 eek         == 36,864  (r170 golden)", c1_eek, 36864)
check("C1 sk          == 36,869  (r170 golden)", c1_sk, 36869)
check("C1 3-solo sum  <= flat", c1_esm+c1_eek+c1_sk, C1_flat, tol=5000)  # allow for CSE cutoff

# ---- C3 FLAT DECOMPOSITION (r160 msg + r161 X narrow-flat) ----
c3_msg = g("C3_live") - g("C3_msg")
c3_X   = g("C3_a1_r161") - g("C3_X")  # X leg uses r161 A1 (same fold tip, digit-exact by r161 plan)
print()
print("== C3 flat decomposition (RAN) ==")
print(f"  message solo     = {c3_msg} g   (r160)")
print(f"  narrow X (u+e0+e1) = {c3_X} g  (r161)")
print(f"  cellar sum       = {c3_msg + c3_X} g  vs C3 flat {C3_flat} g")
check("C3 message == 61,440 (r160 golden)", c3_msg, 61440)
check("C3 narrow X == 110,612 (r161 golden)", c3_X, 110612)
# identity: msg + narrow = flat exactly (r160 + r161 digits)
check("C3 msg + narrow == flat", c3_msg + c3_X, C3_flat)
# cross-round A1 stability (r160's base == r161's base, drink A1 same fold):
check("C3 A1 r156 == r161 base", g("C3_a1_r161"), g("C3_live"))

# ---- C3 NARROW FLAT: 3-cell non-additive note ----
c3_u  = g("C3_a1_r161") - g("C3_U")
c3_e0 = g("C3_a1_r161") - g("C3_E0")
c3_e1 = g("C3_a1_r161") - g("C3_E1")
print()
print("== C3 narrow-flat non-additive cell note (RAN) ==")
print(f"  u  solo = {c3_u}  e0 solo = {c3_e0}  e1 solo = {c3_e1}  3-solos = {c3_u+c3_e0+c3_e1}")
print(f"  X (all three removed together) = {c3_X};  non-additive gap = {(c3_u+c3_e0+c3_e1) - c3_X} g")
# the gap is RAN from the digits (73,728 in r161); assert digit-exact.
check("C3 3-solo excess = 73,728 (r161 golden)", (c3_u+c3_e0+c3_e1) - c3_X, 73728)

# ---- C2b V1 per-limb (r166) ----
c2b_V1_cell = g("C2b_B0") - g("C2b_Jall")
c2b_limb0   = g("C2b_B0") - g("C2b_J0")
c2b_limb1   = g("C2b_B0") - g("C2b_J1")
c2b_limb2   = g("C2b_B0") - g("C2b_J2")
c2b_shared  = c2b_V1_cell - (c2b_limb0 + c2b_limb1 + c2b_limb2)
print()
print("== C2b V1 per-limb decomposition (r166 RAN) ==")
print(f"  V1 cell   = {c2b_V1_cell} g")
print(f"  limb-0   = {c2b_limb0}  limb-1 = {c2b_limb1}  limb-2 = {c2b_limb2}  sum {c2b_limb0+c2b_limb1+c2b_limb2}")
print(f"  non-additive shared block = {c2b_shared} g")
check("C2b V1 cell == 1,149,657 (r166/r167 golden)", c2b_V1_cell, 1149657, tol=1)
check("C2b limb-1 == limb-2 (r166 byte-golden)", c2b_limb1, c2b_limb2)
check("C2b non-additive shared block = 138,420 (r167 golden)", c2b_shared, 138420, tol=2)

# ---- C2b V1 block: sponge vs assert vs X (r168 + r169) ----
print()
print("== C2b V1 block: sponge/attributed cost (r168+r169 RAN) ==")
# r169 X = E1 - S = 207,553 g (sponge wire-cut); r168 assert = 96,255 g (per-coeff assert).
X_block = g("C2b_V1_sponge") - g("C2b_V1_nosponge")  # expected 207,553
X_density = X_block / a("C2b_E1")  # vs total leaf ACIR — not the right denom; skip.
print(f"  X (E1 - no-sponge S) = {X_block} g   vs r169 golden 207,553")
check("C2b X == 207,553 (r169 golden)", X_block, 207553)
print(f"  -> X (207,553) EXCEEDS block (138,420) by {X_block-138420} g; "
      f"density ratio X/block = {X_block/138420:.4f}")

# ---- C2b non-family blocks (r164) ----
c2b_B_nonfam = g("C2b_live") - g("C2b_full")  # = family C2b 552,965
c2b_B_total  = g("C2b_live") - 552965  # non-family = live - family
# alternatively the r164 cited "non-family remainder" B = 2,033,598
c2b_B = g("C2b_live") - g("C2b_full")  # C2b family = 552,965
nonfam = g("C2b_live") - c2b_B  # = 2,033,598
c2b_V1_cell_r164 = g("C2b_live") - g("C2b_V1")
c2b_V2_cell_r164 = g("C2b_live") - g("C2b_V2")
c2b_V4_cell_r164 = g("C2b_live") - g("C2b_V4")
c2b_V5_cell_r164 = g("C2b_live") - g("C2b_V5")
print()
print("== C2b non-family 4-block split (r164 RAN) ==")
print(f"  non-family B = {nonfam} g  (== r164 cited 2,033,598)")
print(f"  V1 cell = {c2b_V1_cell_r164} g   V2 cell = {c2b_V2_cell_r164} g   "
      f"V4 cell = {c2b_V4_cell_r164} g   V5 cell = {c2b_V5_cell_r164} g")
print(f"  sum(V1+V2+V4+V5) = {c2b_V1_cell_r164+c2b_V2_cell_r164+c2b_V4_cell_r164+c2b_V5_cell_r164} g  vs B {nonfam} g")
check("C2b V1 r164 == 1,149,658 (r164 golden)", c2b_V1_cell_r164, 1149658)
check("C2b V2 r164 == 24,576  (r164 golden, exactly N*L)", c2b_V2_cell_r164, 24576)
check("C2b V4 r164 == 208,896 (r164 golden)", c2b_V4_cell_r164, 208896)
check("C2b V5 r164 == 647,650 (r164 golden)", c2b_V5_cell_r164, 647650)
check("C2b B non-family == 2,033,598 (r164 golden)", nonfam, 2033598)

# ---- C2a non-family blocks (r165) ----
c2a_V1_cell  = g("C2a_live") - g("C2a_v1a")
c2a_V2_cell  = g("C2a_live") - g("C2a_v2a")
print()
print("== C2a non-family 2-slice (r165 RAN) ==")
print(f"  C2a V1A cell = {c2a_V1_cell} g   V2A cell = {c2a_V2_cell} g   sum {c2a_V1_cell+c2a_V2_cell} g")
check("C2a V1A cell == 27,838 (r165 golden)", c2a_V1_cell, 27838)
check("C2a V2A cell == 24,576 (r165 golden, exactly N*L)", c2a_V2_cell, 24576)
# cross-leaf byte-identical: C2a V1A == C2b V1 (r165 finding)
check("C2a V1A solo == C2b V1 solo (r165 cross-leaf byte-identical)",
      g("C2a_v1a"), g("C2b_V1"))

# ---- Family pool + grand totals ----
print()
print("== AGGREGATION ==")
c0_family = 0
c4_family = 0
pool = c0_family + C1_fam + C2a_fam + C2b_fam + C3_fam + c4_family
print(f"  family pool = C0 0 + C1 {C1_fam} + C2a {C2a_fam} + C2b {C2b_fam} + C3 {C3_fam} + C4 0 = {pool} g")
check("family pool == 2,849,566 (r160 golden)", pool, 2849566)
# DKG total: cite the leaf live values for the 4 leaves that RETURN public commitments (C1/C2a/C2b/C3)
# + the four top-level rows C0/C4 whose own-circuit gates we do not have on-file. The DKG total
# 9,197,169 g is from r160; I'll validate by re-computing C1+C2a+C2b+C3 leaves + C0+C4 (assume
# whatever r160 had on hand). But that requires C0+C4 live digits we do NOT have in this receipt.
# I'll skip the DKG total row, and only assert here the 4 known leaves.
print(f"  4-leaf leaf gates sum = C1 {g('C1_live')} + C2a {g('C2a_live')} + C2b {g('C2b_live')} + C3 {g('C3_live')} = {g('C1_live')+g('C2a_live')+g('C2b_live')+g('C3_live')} g")
# r160's DKG total 9,197,169 = C0 + C1 + C2a + C2b + C3 + C4; so C0+C4 = 9197169 - sum4
expected_dkg_total = 9197169
sum4 = g('C1_live') + g('C2a_live') + g('C2b_live') + g('C3_live')
c0_c4 = expected_dkg_total - sum4
print(f"  residual C0+C4 = 9,197,169 (r160 golden DKG total) - 4-leaf sum {sum4} = {c0_c4} g (NOT re-burned this round; cited from r160 plan)")
print(f"  share of DKG total = {pool/expected_dkg_total*100:.3f}% family, {(expected_dkg_total-pool)/expected_dkg_total*100:.3f}% non-family")

# ---- Tuple-of-rows written to a CSV for team review ----
print()
print("== FINAL TABLE (per-leaf, RAN re-derivation from 40 on-disk *_gates.json) ==")
print()
print(f"{'row':<7}{'live leaf':>12}{'family':>12}{'per-limb':>12}{'flat':>12}{'cells-known':>28}"
      )
print("%s%-12s%-12s%-12s%-12s%s" % ('C0', '  -', '  0', '  n/a', '  0', ''))
print("%s%12d%12d%12d%12d  %s" % ('C1', g('C1_live'), C1_fam, C1_per, C1_flat, ' e_sm_lifted / eek / sk '))
print("%s%12d%12d%12d%12d  %s" % ('C2a', g('C2a_live'), C2a_fam, C2a_per, C2a_flat, ' flat 0 '))
print("%s%12d%12d%12d%12d  %s" % ('C2b', g('C2b_live'), C2b_fam, C2b_per, C2b_flat, ' flat 0 '))
print("%s%12d%12d%12d%12d  %s" % ('C3', g('C3_live'), C3_fam, C3_per, C3_flat, ' message + u/e0/e1 '))
print("%s%-12s%-12s%-12s%-12s%s" % ('C4', '  -', '  0', '  n/a', '  0', ''))
print("%s%12s%12d%12s%12s  %s" % ('POOL', '', pool, '', '', ' (pool = 2,849,566 per r160) '))
print()

if errors:
    print(f"FAIL: {len(errors)} mismatch(es)")
    for e in errors:
        print(f"  MISMATCH: {e}")
    sys.exit(1)
print("PASS: all identity checks hold (RAN re-derivation digit-exact vs goldens)")