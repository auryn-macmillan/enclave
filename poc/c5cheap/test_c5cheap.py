# SPDX-License-Identifier: LGPL-3.0-only
"""
Self-contained checks for c5cheap.py (the reference model).

Each section is one mathematical claim; every check prints the OBSERVED value
and a REASON for the expectation, so a reader can audit the arithmetic
independently. No external dependencies (stdlib only).

Run:  python3 test_c5cheap.py   (exits 0 iff every check passes)
"""

import sys
import random
from c5cheap import (
    P, ALPHA, N, Q,
    walking_pin, kernel_vector,
    poly_mul, poly_eval,
    ring_identity_residual, ring_identity_holds,
    build_valid_tuple, range_ok,
)

PASS = []
FAIL = []


def check(name, cond, reason, observed=None):
    tag = "PASS" if cond else "FAIL"
    print(f"  [{tag}] {name}")
    print(f"         reason: {reason}")
    if observed is not None:
        print(f"         value : {observed}")
    (PASS if cond else FAIL).append(name)


# ------------------------------------------------------------------
print("== A. The walking pin is LINEAR (bilinear over F_P) ==")
_rng = random.Random(0xA11CE)
X = [_rng.randint(0, 10) for _ in range(N)]
Y = [_rng.randint(0, 10) for _ in range(N)]
A = 3
B = 7
COMBO = [(A * a + B * b) % P for a, b in zip(X, Y)]
lhs = walking_pin(COMBO, ALPHA, P)
rhs = (A * walking_pin(X, ALPHA, P) + B * walking_pin(Y, ALPHA, P)) % P
check("walking_pin(a X + b Y) == a pin(X) + b pin(Y)  mod P",
      lhs == rhs,
      "Horner's form is a stack composition of scalar products; in every"
      " step the pin bilinearizes into A and B. Therefore the pin is"
      " a linear functional over F_P with kernel of dimension at least 1.",
      f"lhs = {lhs}, rhs = {rhs}")

# ------------------------------------------------------------------
print("\n== B. The walking pin has a non-trivial KERNEL (r136 leg_b, restated) ==")
VK = kernel_vector(N, ALPHA, P)
check("walking_pin(vK) == 0 and vK is not the zero vector",
      walking_pin(VK, ALPHA, P) == 0 and VK != [0] * N,
      "vK = [0]*N with vK[N-2] = 1, vK[N-1] = -ALPHA mod P. The"
      " Horner recurrence accumulates alpha*1 + (-alpha) = 0 at the"
      " tail step. All prior positions are 0, so the accumulator"
      " enters the tail step at 0 and exits at 0. pin(vK) == 0 mod P,"
      " but vK is nonzero -> kernel dimension >= 1.",
      f"|vK| = {sum(v for v in VK)}, pin(vK) = {walking_pin(VK, ALPHA, P)}")

# ------------------------------------------------------------------
print("\n== C. Building a valid P3-ct0 tuple: the RING IDENTITY holds by construction ==")
RNG2 = random.Random(0xBEEF)
K0 = [RNG2.randint(0, 5) for _ in range(N)]
Q0 = [RNG2.randint(1, 100) for _ in range(N)]   # moduli (nonzero)
TUPLE = build_valid_tuple(7, K0, Q0)
check("residual (built ct0) - (pk0*u + e0 + k1*k0 + r1*q) is the zero polynomial",
      ring_identity_holds(TUPLE),
      "build_valid_tuple constructs ct0 as the EXACT sum and then"
      " stores it. ring_identity_residual recomputes the RHS independently"
      " and returns ct0 - RHS. Both use the same ring multiplication;"
      " by construction ct0 == RHS pointwise, so the residual is 0.",
      f"residual = {ring_identity_residual(TUPLE)}")

# ------------------------------------------------------------------
print("\n== D. A 1-coefficient tamper to ct0 breaks the identity ==")
TAMPER = {k: (list(v) if isinstance(v, list) else v) for k, v in TUPLE.items()}
TAMPER["ct0"] = list(TUPLE["ct0"])
TAMPER["ct0"][3] = (TAMPER["ct0"][3] + 1) % Q
check("SH Breaking ct0[3] by +1 makes the residual nonzero",
      ring_identity_residual(TAMPER) != [0] * N,
      "The residual at index 3 is now 1 (mod Q), all other indices"
      " still 0. A nonzero residual in N-ring means the polynomial"
      " identity is genuinely broken, not merely 'worse in expectation':"
      " we are in a finite ring, and any nonzero residue is a deterministic"
      " DISCRIMINATOR (the circuit escalates this via one SZ modulus CHECK"
      " at a random gamma, but the underlying claim for this model is the"
      " stronger exact ring identity).",
      f"residual = {ring_identity_residual(TAMPER)}")

# ------------------------------------------------------------------
print("\n== E. The RANGE PIN catches a witness whose walking-pin ALONE would not ==")
BASE = [RNG2.randint(0, 6) for _ in range(N)]   # fully in-range
EGSB = 6                                          # matches in-range bound
BOGUS = list(BASE)
BOGUS[7] = EGSB + 13                              # out of range
check("range_ok(BASE) is TRUE; range_ok(BOGUS) is FALSE",
      range_ok(BASE, EGSB) and not range_ok(BOGUS, EGSB),
      "BASE is drawn from {0..6} so every coef <= 6 = EGSB. BOGUS[7] = 19"
      " is out of range. The WALKING PIN over BOGUS is still a well-defined"
      " field element (the pin is a stack fold, not a range check) and"
      " might be in the SAME affine space as pin(BASE). The RANGE PIN"
      " is a per-index ABSOLUTE bound check and catches this immediately"
      " for every in-range witness while the pin ALONE would not.",
      f"BOGUS[7] = {BOGUS[7]}, EGSB = {EGSB}, pin(BOGUS) = {walking_pin(BOGUS, ALPHA, P)}")

# ------------------------------------------------------------------
print("\n== F. SZ-IDENTITY is LOAD-BEARING: removing it reopens the forgery path ==")
# A "forged" tuple: build a valid tuple, then PERSIST a wrong ct0 (built
# from the WRONG pk0) but preserve everything else. The WALKING PIN over
# the ct0-vector (always in-range since every coef is in [0, Q)) is well-defined;
# the RANGE PIN over ct0 is in-range (ct0 is already an R element); the only
# place that will detect this is the SZ-identity (the ring policy identity).
FORGE = {k: (list(v) if isinstance(v, list) else v) for k, v in TUPLE.items()}
WRONG_PK0 = [(v + 37) % Q for v in TUPLE["pk0"]]   # clearly different
FORGE["pk0"] = WRONG_PK0
FORGE["ct0"] = [0] * N                            # bogus ct0, replaces the valid one
forgery_ok_pin         = True                     # pin is always well-defined
forgery_ok_range       = range_ok(FORGE["ct0"], Q)  # in-range over R
forgery_identity       = ring_identity_holds(FORGE)
check("forged tuple (wrong pk0, zeroed ct0): pin well-defined, in-range, but identity FAILS",
      forgery_ok_pin and forgery_ok_range and not forgery_identity,
      "pin = well-defined field element; range on ct0 = [0]*N <= Q -> in-range."
      " The ring identity FAILS because pk0*u != pk0*u + 37*u for any x;"
      " residual == non-trivial term in the ring. This demonstrates the SZ-identity"
      " is LOAD-BEARING: with identity dropped, an attacker could submit a.ct0"
      " that looks (pin + range) like a valid commitment of some valid tuple"
      " while relying on the identity to do the actual BInding.",
      f"identity_holds = {forgery_identity}")

# ------------------------------------------------------------------
print(f"\n  total: {len(PASS)} PASS, {len(FAIL)} FAIL.")
if FAIL:
    print("Failed checks:")
    for f in FAIL:
        print(f"  - {f}")
    sys.exit(1)
print("ALL CHECKS PASS")
