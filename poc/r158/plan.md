# r158 — C2a + C2b per-limb/flat split @ FOLD base 3291d85bd (round 158 post DIRECTION RESET)

## Idea
Close the RESUME RULE p1 from r157: C2a + C2b per-limb/flat split on the fold-base table.
r152d shipped per-leaf totals for the C2a/C2b twins (552,965 g family each, digit-invariant
across c98b and d62e bases) but never sliced them into per-limb vs flat -- the last unsliced
surface on the fold-base family pool (2,849,566 g = 30.98% of the DKG total at fold base 9,197,169).

The Spec-A discriminator question: is the dominant share of the C2a/C2b family the per-limb
span (a `for mod_idx in 0..L { ... }` block) or the flat portion (something outside a per-limb
loop, like C1's eek/sk/e_sm_lifted polys or C3's flat polys + quotient)? r156 (C3) =
76.40% per-limb / 23.60% flat; r157 (C1) = 79.94% per-limb / 20.06% flat. The C2a/C2b row is
the last remaining row the Spec-A family-discriminator test needs.

## Method
- 4 legs, all RAN in-session on the 8c/31 GiB/0swap box (taskset -c 0-3, `time -v` for peak):
  - A: unblunt C2a at fold base -- sanity re-anchor vs r152d golden 1,464,743 g.
  - B: C2a with the entire check_range_bounds fn body line-commented -> family price = A - B.
  - C: C2a with only the per-limb content commented; the for-headers + closing braces +
    blank/comment lines KEPT -> per-limb price = A - C; flat (scaffold) price = C - B.
  - E: unblunt C2b (complementary sanity leg; r152d golden 2,586,563 g).
- Worktree /tmp/r158 @ 3291d85bd (detached). Artifact at
  circuits/bin/dkg/target/{sk_..._share_computation,e_sm_share_computation}.json. Preset
  flip insecure-512 -> secure-8192; both DEF and SC sha-pinned pre and post (7f07de82 /
  44eb78d7, the same two shas r152d pinned).
- Porc 0 before and after; 3 backup refs live (7e999546e, 3e4bcc776, 4519f68fe); EB
  c98b0d1caa31 in origin/main LOCKED (is-ancestor rc 0); origin f2df52907 UNMOVED.

## Source-read premise (the shape the RAN was expected to confirm)
circuits/lib/src/core/dkg/share_computation.nr L258 defines the shared helper that C2a
(SecretKeyShareComputation::execute) and C2b (SmudgingNoiseShareComputation::execute) both call:
check_range_bounds is a 3-deep `for mod_idx / for coeff_idx / for party_idx` loop of
Polynomial::new(...).range_check_standard(q_j) calls. The ENTIRE fn body is the per-limb triple
loop; there is no non-loop statement inside it. Expected RAN: B == C (whole-fn NOP == per-limb
content NOP), so family - per-limb = flat == 0, i.e. the C2a family is 100% per-limb.

## RAN results
leg | gates | ACIR | wall_s | peak_kB
- A (C2a unblunt)        1,464,743  442,744  169.5  4,741,180
- B (C2a whole-fn-NOP)     911,778   221,560  161.6  4,746,644
- C (C2a per-limb-only)    911,778   221,560  163.0  4,695,872
- E (C2b unblunt sanity) 2,586,563   854,722  216.2  5,738,128

Decomposition (from on-disk A/B/C digits; identity holds because B and C RAN digit-equal):
- C2a family   = A - B = 552,965 g = 37.75% of A leaf. Digit-identical to the r152d golden.
- C2a per-limb = A - C = 552,965 g = 37.75% of A leaf = 100.00% of family.
- C2a flat     = C - B = 0 g = 0.00% of leaf / 0.00% of family.

Cross-base (c98b -> fold): A fold 1,464,743 vs r152d 1,464,743 (delta 0); family fold 552,965
vs r152d 552,965 (delta 0, the r152d base-invariance carries across #1996 + fold); E C2b
fold 2,586,563 vs r152d 2,586,563 (delta 0). All four rows of the fold-base
table carry over digit-exact on the C2 rows.

## Verdict: RAN
C2a's family (552,965 g) is 100% per-limb / 0% flat, proven by RAN leg equality B == C --
a direct measurement, not a source-read inference. This is the purest per-limb lattice on the
DKG family table: C1 79.94% / C3 76.40% / C2a 100%. C2b is the C2a twin (r152d digit-identical
family 552,965 across both bases); the E leg RAN-reconfirms C2b's leaf 2,586,563 at fold base,
and C2b shares the same check_range_bounds locus + the same triple-loop shape, so its family is
predictably 100% per-limb too (RAN claim made for C2a + E; C2b split NOT recomputed this round
to stay inside budget -- it is the twin of a RAN already).

The flat == 0 itself is load-bearing: the C2a/C2b family has no flat carve-out, so any
per-limb aggregate-bound redesign (the owner-gated C6-class lever, gate 5, still closed -- not
re-opened here) touches only the per-limb span, which is the entire family. That is the
cleanest Spec-A surface on the table and the one that a single-pass per-limb bounded-proof
redesign would convert to a per-limb floor with no residual flat cost.

## Mutations
- Receipts-only work on i5/dkg-research (17 files in poc/r158/, 0 circuits/ source, 0 crates/).
  Parent = 3291d85bd (r157 commit, verified this round via git rev-parse HEAD^). The r158
  commit's SHA can SHIFT with the plan.md crest-cycle (a commit can't embed its own final
  hash), so the stable identifiers are the branch name (research/r158-c2ab-per-limb-split)
  on the private enclave remote and the stable parent chain 3291d85bd (r157) / 247298ad5 (r156).
- Review branch research/r158-c2ab-per-limb-split created from that commit and pushed to the
  private enclave remote (ssh://git@github.com/auryn-macmillan/enclave). NOT origin/theinterfold;
  NOT main; NOT a force-push. (Enclave ship / force-push stays owner-gated per the standing
  clause.)

PROVENANCE NOTE (verified this round against `git ls-remote --heads enclave`):
enclave remote's most recent previously-pushed research branch was r155 (tip 74381599f);
r155's base is 54 commits below. r156 (247298ad5) and r157 (3291d85bd) all sat LOCAL-ONLY
on the i5/dkg-research working branch. The new review branch research/r158-c2ab-per-limb-split
is 149 commits ahead of the r155 ref (common base 2135f9063f). Pushing it creates a NEW
remote ref (NO existing enclave ref was rewritten); the tip hash moves with the final
plan.md patch but the branch name and uplift are stable. Side effect: the whole
i5/dkg-research working line is now reviewable on enclave; LOCAL-ONLY and ENCLAVE carry
the same commit set after this round completes.
- STATE.md line-1 splice (TICK-607/R158 prepended above TICK-606). LOG.md dated 2026-10-07 entry.
- /tmp/r158 worktree add + prune.

## Notes on round hygiene (honest)
This round had two harness faults before the clean run, both caught and logged (skill
corrections-first): (1) the first B/C run compiled the LEGACY `''`.join vs `'\n'.join` bug
that squashed the 13 fn-body lines into one line-comment, swallowing the fn's closing brace
-> 71 nargo errors mid series; (2) pass-2 ran B/C under the insecure-512 preset (leg A skip
meant the flip was not re-run) -> B == C == 28,535 g under insecure-512. Both stale B/C
receipts were deleted; the final B/C numbers (911,778 / 911,778) are the clean secure-8192
re-run. A (1,464,743) and E (2,586,563) were valid from the first pass (digit-identical to
r152d goldens) and were reused, not re-burned.