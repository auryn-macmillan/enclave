# r147 soundness note — C3 per-limb aggregate-bound prototype

## What the round measures (C3, share_encryption, secure-8192 / minimum, N=3/T=1/H=2)

C3's `check_range_bounds()` (share_encryption.nr:295-331) is two disjoint blocks:

1. **Flat polynomials** — u, e0, e1, message: 4 per-coefficient range checks
   (BIT_U=1, BIT_E0=5, BIT_E1=5, BIT_MSG=58 at secure-8192), each an N=8192-term
   per-coeff range.
2. **Per-limb polynomials** — `pk0is[L]`, `pk1is[L]`, `r1is[L]`, `r2is[L]`,
   `p1is[L]`, `p2is[L]` at L=2 moduli ⇒ 12 per-limb polynomials, each an N (or
   2N) per-coeff range check (BIT_PK=59, BIT_R1=55, BIT_R2=59, BIT_P1=13,
   BIT_P2=59 per `configs/secure/dkg.nr`).

Three RAN legs price the family:

| Leg   | Configuration                                                       | Gates     | Meaning                                  |
|-------|---------------------------------------------------------------------|----------:|-------------------------------------------|
| C3A   | in-tree as-is (unblunt re-anchor)                                   | 2,966,353 (golden, r39/r41/r75/r84; r145/r146 twin) | FLOOR  |
| C3B   | `check_range_bounds()` call fully NOP'd (r146 shape)                | 1,827,697 (r146 twin)                      | family ceiling (all 16 polynomials removed) |
| C3C   | 4 flat polynom checks stay; per-limb for-loop commented             | 1,999,749 (fresh; SHA 4f0d58f2)             | **isolates the per-limb slice**         |

## RAN quotable deltas

- **Total range family** Δ_total = C3A − C3B = **1,138,656 g** (r146 RAN-confirmed)
  = **38.39 % of the C3 leaf** / **9.85 % of the 11.558M-g DKG base**.
- **Per-limb slice** Δ_limb = C3A − C3C = **966,604 g** (this round's C3C RAN)
  = **32.59 % leaf** / **8.36 % DKG base**.
- **Flat slice** Δ_flat = C3C − C3B = **172,052 g** (4 flat poly checks only)
  = **5.80 % leaf** / **1.49 % DKG base**.

Identity check (all RAN inputs): 966,604 + 172,052 = 1,138,656 = Δ_total. ✓
Per-limb = 84.9 % of the C3 range family; flat = 15.1 %.

## What the "r115 C6 class" means concretely here

r115 ("C6 production field anchor", −13.943 % at secure-8192, RAN) delivered an
I14-class ahead-dedupe on C6's `share_decryption.nr` payload — not a range family.
The queue item (1) phrase "r115 C6 class" points at the *shape of the redesign*:
replace a per-coeff range family with a **per-polytop aggregate bound** (one compact
valiny witness per polytop, not one N-term per-coeff range), mirror to whatever
lever we want to land. For C3 specifically:

> Replace the **12 per-limb per-coeff range checks** (the per-limb for-loop,
> 966,604 g in RAN) with a **small end-check per (polytop, limb)** — an
> O(L·6) aggregate bound per polytop + a compact "all coefficients are < bound"
> assertion per limb, so that a limb whose bound is violated fails exactly
> as the current per-coeff check would. Typical prior term (59-bit per coeff ×
> 8192 coeffs × 6 polytops × 2 limbs = **58,368,000** gate-bit terms) collapses
> to O(6 × 2 × 59) ≈ 708 bound complement (5) + 12 × O(N) sum-modulus adders.

C3-specific caveats (why Spec A is the safe-hex class, why Spec B is not):

1. The CT0/CT1 relations (I15, wired at line 350-355 in
   `share_encryption.nr`) *currently* rely on |e0| < q_l for all l — that bound
   lives in the **flat** e0 polytop (still 5 bits per coeff, not touched by a
   per-limb-only change). So a Spec A (pk/p1/p2/r1/r2 aggregate, flat e0/msg
   untouched) stays binding-invariant with the I15 witness shape; the CT0
   relation is in fact *identical* before and after a Spec-A aggregate — no
   re-suite, no re-eval, no re-gate beyond the 2026-09-12 per-diff sign-off.

2. Spec B also aggregates r1, r2. Risk: r1 carries the modulus-switching quotient,
   |r1| < q_l is a *hard* bound (not a bound-then-complement — the r1 poly's
   coefficient is int to 2N terms). If a Spec-B aggregate admits a r1 coefficient
   in-limb that duit q_l for some limb, the decryption class widens and the
   CT0 `ct0[l](γ) = … + r1[l](γ)·q_l + …`  identity becomes "proved a wider
   class" (an I15-class security adjudication, lines 349-355 of the source).
   Since r1/r2 are *not* part of the ct-binding path (only pk/ct are), a
   Spec-A-only drop leaves r1/r2 per-coff intact and the decryption class is
   provably the same as today.

3. As r146 already RAN-confirmed, the C3 family is a soundness-loaded class
   (not a free cut); the e0 38-bit per-coeff bound in every secure-8192
   decryption relates to |e0| < q_l and that's the flat piece (Spec A does not
   touch it).

## Recommended posture (for owner decision)

- **Spec A (recommended): pk/p1/p2 + r1/r2 aggregate per limb, flat e0/msg/u
  unchanged.** Max RAN delta = 966,604 g (per-limb slice of the C3 family,
  8.36 % DKG base). Expected in-tree reality: −(8.0 to 8.3) g DKG base after
  the aggregate-map wire overhead (DRAFT pending the in-tree spec-A proto).
  Soundness: binding-invariant with the shipped I15 CT0 relation.

This round changes nothing in-tree. A clean measurement-only commit. The in-tree
spec-A proto is the next round once the owner green-lights.

## RAN vs DRAFT — this round

Measurement-only. No in-tree change. The on-disk artifacts in the
`poc/r147/` dir are: the 3 shadow legs, the launcher, the systemd unit file,
this note, and the re-run `A_main.sh`. Tree is byte-exact pre/post; SE.sha =
a7c5b9b9…556f, DEF.sha = 7f07de82…aa20, HEAD = a89e6f451.
Owner eyeballs are the only gate to in-tree spec-A delivery (per the
2026-09-12 per-diff sign-off rule).