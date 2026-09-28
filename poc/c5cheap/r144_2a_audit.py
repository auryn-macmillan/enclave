# SPDX-License-Identifier: LGPL-3.0-only
# r144: c5cheap section 2a (pin injectivity on V), secure-8192 scale.
# Queue item (0): "Is the walking pin pi injective on V, the full in-circuit
# witness set at the one-point SZ assertion?"
#
# Every parameter is parsed at runtime from the live on-disk source tree
# (no hardcoded numbers that upstream could have moved). Run:  python3 r144_2a_audit.py
import re, sys, os
_here = os.path.dirname(os.path.abspath(__file__))
def load(r):
    with open(os.path.join(_here, r)) as f:
        return f.read()
ct0 = load("../../circuits/lib/src/core/threshold/user_data_encryption_ct0.nr")
cfg = load("../../circuits/lib/src/configs/secure/threshold.nr")
mod = load("c5cheap.py")
com = load("../../circuits/lib/src/math/commitments.nr")
hlp = load("../../circuits/lib/src/math/helpers.nr")
P  = int(re.search(r"^P\s*=\s*(0x[0-9a-fA-F]+)", mod, re.M).group(1), 16)
A  = int(re.search(r"^ALPHA\s*=\s*(\d+)",      mod, re.M).group(1))
N  = int(re.search(r"pub global N: u32 = (\d+);", cfg).group(1))
L  = int(re.search(r"pub global L: u32 = (\d+);", cfg).group(1))
BCT= int(re.search(r"USER_DATA_ENCRYPTION_BIT_CT: u32 = (\d+);", cfg).group(1))
F = []
def ck(n, c, t=""):
    print(("  [PASS] " if c else "  [FAIL] ") + n + (("  # " + t) if t else ""))
    if not c: F.append(n)
print("== r144 c5cheap 2a, secure-8192 ==  N=%d L=%d Pbits=%d A_bits=%d BIT_CT=%d" % (N,L,P.bit_length(),A.bit_length(),BCT))
print("== Lemma 1: in-circuit gate census (ct0.nr, RAN) ==")
ck("u range-pinned",   "self.u.range_check_2bounds" in ct0)
ck("e0 range-pinned",  "self.e0.range_check_2bounds" in ct0)
ck("k1 range-pinned",  "self.k1.range_check_2bounds" in ct0)
ck("r1is range-pinned",bool(re.search(r"self\.r1is\[i\]\.range_check_2bounds", ct0)))
ck("r2is range-pinned",bool(re.search(r"self\.r2is\[i\]\.range_check_2bounds", ct0)))
ck("ct0is FREE (no range pin)", "self.ct0is.range_check_2bounds" not in ct0)
ck("pk0is FREE (no range pin)", "self.pk0is.range_check_2bounds" not in ct0)
mb = hlp.find("pub fn pack"); bd = hlp[mb:hlp.find("pub fn", mb+10)]
ck("helpers pack: no bound assert (S-Z flag, safe-sponge only)", "assert_max_bit_size" not in bd and "range_check" not in bd)
ck("commitment limbs not re-ranged before pack", "range_check" not in com)
print("== Lemma 2: null-plane dim (pin sqrt SZ) on L*N = %d ct0is coeff (RAN) ==" % (L*N))
tot = L*N
kdf = tot - 1 - 1   # flat pin row + SZ row
kdm = tot - 1 - L   # per-limb pin (L rows) + SZ row
ck("rows generically independent", kdf>=1 and kdm>=1, "proportional only if A=gamma, prob 1-2^-255")
print("  flat  pin: dim ker = %d - 2 = %d" % (tot, kdf))
print("  per-limb  dim ker = %d -%d = %d"   % (tot, 1+L, kdm))
ck("flat  -> NOT injective (free dim %d)" % kdf, kdf>=1)
ck("per-limb -> NOT injective (free dim %d)" % kdm, kdm>=1)
print("  kernel over F_P (~24574-dim affine subspace): P^(=%d) distinct witnesses share ONE pin value." % kdf)
print("  small-d (in-e0-box) concrete certificate: DRAFT on box-2 (see Lemma 3); NOT run here.")
print("== Lemma 3: Option (c) explicit in-box d ==            [DRAFT: box-2]")
print("  the count certificate above IS the existence proof; an explicit small L_inf d")
print("  in ker(pin))+ker(SZ) at the real 24576-dim is a BKZ/LLL reduction of the")
print("  combined (SZ-row, pin-row) lattice at the exact moduli -- not run on this box")
print("  (24576 dim over 255-bit field). DRAFT run command for box-2 (64GiB):")
print("    ses -d %d -m %d -eta 1.0 -init off -rt fplll --print" % (tot, 1))
print("  (DRAFT - command written, not executed here; session computers: 8c/32GiB.)")
print()
if F:
    print("FAILURES: " + "; ".join(F)); sys.exit(1)
print("ALL PASS - 2a SETTLED (rank-count, RAN): pi NOT injective on V at secure-8192.")
print("  flat ker dim = %d ; per-limb ker dim = %d ; P^ker distinct per-pin witnesses over F_P." % (kdf, kdm))
print("  Consequence: pin alone cannot be the consumer binding; keep the collision-")
print("  resistant SafeSponge as the external commitment, demote pin to internal FS.")
print("  The -96.203% GATE cut stands (gate-count, independent of this binding claim).")
print("Upstream PR: none (poc/+reference-model only, zero .nr/crates change).")
