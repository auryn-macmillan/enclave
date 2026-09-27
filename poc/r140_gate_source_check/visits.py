#!/usr/bin/env python3
# r140 gate source-check - reproducible RAN probe (re-runs the numbers in RAN.out).
# Reads A and P from the on-disk r136 probe (byte-copy, no re-typed hex).
import re, os

HERE = os.path.dirname(os.path.abspath(__file__))
src = open(os.path.join(HERE, "..", "r136", "leg_b.py")).read()
P = int(next(l for l in src.splitlines() if l.startswith("P = ")).split("=")[1].strip(), 16)
A = int(next(l for l in src.splitlines() if l.startswith("A = ")).split("=")[1].strip())

Q1 = 0x02000000015a0001   # fhe-params constants.rs MODULI Sec8192, largest limb
Q2 = 0x0200000001460001
Q3 = 0x0200000001210001
Q = max(Q1, Q2, Q3)
N = 8192
BIT_MSG = 58

print("== r140 gate source-check RAN probe ==")
print("P =", P, "(%d bits)" % P.bit_length())
print("A =", A)
print("Q (secure-8192 max limb) =", Q, "= 0x%x (%d bits)" % (Q, Q.bit_length()))
print("N = %d, BIT_MSG = %d, flat payload len = %d" % (N, BIT_MSG, N * BIT_MSG))
print()

# [K] r136 kernel vector re-confirm + in-box check
k = [0] * N
k[N - 2] = 1
k[N - 1] = (P - A) % P
acc = 0
for x in k:
    acc = (acc * A + x) % P
in_box = all(0 <= v < Q for v in k if v != 0)
print("[K] kernel vector k[N-2]=1, k[N-1]=(P-A) mod P, pin(k) =", acc)
print("[K] in-box (all coords < Q)?", in_box,
      "  max coord bits =", max(k).bit_length(), " vs Q bits =", Q.bit_length())
print()

# [V] pigeonhole / entropy bound: how many IN-BOX witnesses map to one acc value.
# The C4 secret = N=8192 coefficients each in [0, Q) (Q ~ 2^58).
# In-box secret entropy <= N * log2(Q+1) bits.  The acc-pin output is log2(P) bits.
# => a generic acc value has >= 2^(secret_bits - P_bits) distinct in-box witnesses.
secret_bits = N * (Q + 1).bit_length()
fiber_bits = secret_bits - P.bit_length()
print("[V] in-box secret entropy ceiling  = N * bits(Q) = %d * %d = %d bits" % (N, (Q + 1).bit_length(), secret_bits))
print("[V] acc-pin output = %d bits (one BN254 field element)" % P.bit_length())
print("[V] lower bound on IN-BOX witnesses per acc value = 2^(%d - %d) = 2^%d" % (secret_bits, P.bit_length(), fiber_bits))
print("[V] => acc-pin + per-coeff range box is NOT injective: a ~%d-bit in-box fiber remains;" % fiber_bits)
print("    range pins only remove the ~%d-bit OUT-of-box coords; they do not close the fiber." % (P.bit_length() - (Q + 1).bit_length()))
print()

# [D] kernel out-of-box gap
kN = (P - A) % P
print("[D] k[N-1] =", kN, "(%d bits)" % kN.bit_length())
print("[D] gap: k[N-1] is about %x the per-coeff box bound Q (bit gap %d bits)" % (kN // Q, kN.bit_length() - Q.bit_length()))
print("END")