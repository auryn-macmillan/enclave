r154 C6 (threshold/share_decryption) I14 @ PRODUCTION shape (confirmation-leg): secure-8192/small (N=19/T=9/H=14)
Unblunt V0 vs 5-site I14 shadow V1 (5-site form from r153 V1-using, re-applied here; NOT shipped).
c98b0d1ca base, nargo 1.0.0-beta.26 + bb 5.1.0, taskset 0-3, /tmp/r151b.
V0 (unblunt, prod shape)    = 2,601,164 g / ACIR 524,709 / wall 92.64 s (user 89.91 / sys 2.75) / peak-sample 7,107 MB / sha 2141bf1ade614d4e68ace38be84c3d5e0b9f1b9a942ebf77d9f34a6cfae3eac6
V1 (r115 I14 5-site, prod)  = 2,186,053 g / ACIR 486,488 / wall 54.67 s (user 52.59 / sys 2.14) / peak-sample 3,844 MB / sha 659345f660ee42a9ccb3023c56ff6dc2319332adce79b009cc62d1160db41979
DELTA = 415,111 g = 15.959% of the C6 leaf at secure-8192/R-shape-invariant (RAN).

KEY FINDING (correction to the prior caption's framing, r154):
C6's bin/threshold/share_decryption/src/main.nr imports only
  `lib::configs::default::{N=8192, L=3, MAX_MSG_NON_ZERO_COEFFS, THRESHOLD_SHARE_DECRYPTION_BIT_*, THRESHOLD_SHARE_DECRYPTION_CONFIGS}`
and `lib::core::threshold::share_decryption::ShareDecryption`. It does NOT read
  `lib::configs::committee::active::{N_PARTIES, T, H}`
(committee-size-independent at N=8192 by source — verified by grep on both files and by the
load-time identity of this leg's V0 with r153's minimum-shape V0 at the same
c98b0d1ca base: both legs compile to sha256 2141bf1a under `nargo compile --force`,
a fresh-compile equivalence a stale-artifact trap or mis-shape probe would not produce).
Consequence: the r153 RAN delta of -415,111 g = -15.959% at minimum N=3 already equals the
production-shape RAN delta. The "different N, different gates" worry encoded in the in-tree
correction's threat model is a NULL hypothesis for C6 under R-shape-independent compilation.
The 5-site I14 shadow delta therefore carries to production N=19/T=9/H=14 with the SAME numeric
value, and the in-tree stylistship risk window is committee-size-neutral at this compilation shape.

ARTIFACT HYGIENE (correction to prior caption):
- V0 fresh sha 2141bf1a is the SAME fresh sha as poc/r153/V0 (same compile, different
  `nargo compile --force` invocation; a `--force` re-compile of identical source + identical
  IR reproduces the identical fresh artifact at this shape — strong evidence the flip was a
  source-level no-op, not a trap that re-plotted r153's pre-existing artifact).
- V1 fresh sha 659345f6 (r154) vs 51d7cc7a (r153) differs while the gate count is
  identical (2,186,053 in both). The expected class is a fresh-compile backend
  timestamp/uuid region, but this round has not run a double-compile variance probe
  to independently close it; the gate-equality is the load-bearing invariance and
  is unaffected by the open sha-variance question.

RESTORE-CONTEXT pre-pins: DEF=7f07de82407c9601dd737044af69a068238dd9ff175f51c4d64d8e00980aa207 ACT=0bf0cc642ddfa98d48f51f7d007dc6749e9c1d4b4b02c36d9e1da1d4735d0ac4 SDNR=5fe8ee6ca36405e7ebc7cb7ea91a7dd9d0de5b85af4e6941387118b9616e56f2 PRE_JSON=2141bf1ade614d4e68ace38be84c3d5e0b9f1b9a942ebf77d9f34a6cfae3eac6
