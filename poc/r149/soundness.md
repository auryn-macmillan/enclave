# r149 — C1 (pk_generation) range family: soundness posture

C1's range family (eek BIT_EEK, sk BIT_SK, per-limb e_sm/r1/r2 across L=3 moduli) is
the C1 analog of the C2/C3 per-coefficient range families priced in r145-r147.

## The family is security-load-bearing, same class, one tag difference

The source states it in one line (pk_generation.nr:155-156): "these bounds are critical
for BFV security - large coefficients would break the scheme's hardness assumptions
(Ring-LWE)." The C1 range checks pin the ring-LWE component size (sk, eek, and the r1/r2
modulus-switching quotients) below the security bound; they are NOT the binding. Same
posture as the C2a/C2b r34 tag and the C3 family: family size is the quotable research
fact; the family is NOT free to cut.

## Deltas and lever

If C1C (per-limb slice) comes out comparable in LEAF-PERCENT to C3's (32.59%) - the
DESIRABLE structural outcome given the two circuits have the same witness shape -
then a Spec-A aggregate-bound redesign at C1 would attack a slice in the same
~7-8%-of-DKG-base class as C3's. C1+C3+ C2a/C2b combined as a single C6-class
redesign family then becomes the largest coherent lever on the DKG base measured by
this whole project (≈ 8.36+7-8+4.78+4.78 ≈ 25-26% of the 11.558M-g DKG base).

## What this round does NOT answer

- Whether an aggregate (chunk/chip-level) bound on e_sm/r1/r2 is BINDING-EQUIVALENT
  to the per-limb range checks at C1 - that is the spec-A redesign work, not a
  shadow-NOP leg. The r147 Spec-B caveat applies here too: aggregating the r2
  accumulation/reduction quotients re-adjudicates the cyclotomic-reduction wire
  shape and is NOT recommended.
- The BOUND-LOSS RISK of an aggregate bound: a per-coeff max |x_i| < B is STRICTLY
  STRONGER than the per-limb aggregate upper bound the redesign would instead pay for;
  that particular swap is a genuine adversarial-level downgrade requiring its own fresh
  adversarial analysis. For C3 (r147) the flat e0/message witness shape carries the I15
  binding, so the per-limb aggregate was CLASS-level binding-invariant; at C1 the sk/eek
  flat checks stay interleaved in-range of the per-limb quotient family, so the
  adversarial-repair analysis needs its own round before shipping.

## Bottom line (wait for legs to land)

Per-limb family slice ≤ total family slice ≤ leaf gate count are the only quotable
research facts from a shadow-NOP leg. Whether a real in-tree reduction at C1 lands
AND is security-equivalent to the shipped shape is NOT answered here; it is the
Spec-A-family work, owner-gated.

UPSTREAM-PR: none (measurement-only; source restored byte-exact per-leg).