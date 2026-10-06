# r156 - C3 receipt re-anchor @ fold base 7e999546e (+ c98b control leg)
## Purpose
r152b c98b ledger (C3A 2,125,396 / C3B 1,396,286 / family 729,110) is still the
nearest RAN anchor, but the tree base moved (folded 6294250f6: #1996 V0.4.1
reshaped the C3 locus to 767 lines; our i5 I3 commit then removed the raw k1 push loop from the sponge (code change, replaced by a comment)
a38431229). R156 re-measures the C3 leaf at the fold base and splits the
range family into per-limb and flat slices (r147 class).
## Legs (all RAN, DEF flip + pull, valve WTBIN of circuits/bin/dkg)
- C3A_live  = 2,124,549 g  ACIR 609,966  peak 20.8 GiB
- C3B_full  = 1,395,432 g  ACIR 224,942  (check_range_bounds fully inoperative)
- C3C_limb  = 1,567,484 g  ACIR 347,822  (per-limb slice inoperative; flat 4 polys preserved)
- c98bA     = 2,125,396 g  ACIR 609,966  c98b0d1ca control -> flip shape reproduces r152b multi-run RAN exactly (delta 0)
## Decomposition (from on-disk gate JSON; the leg script's sum block wrongly printed family - flat as the per-limb term, and carried one wrong constant 476,693 -- not a RAN number, struck)
- family        = C3A - C3B = 729,117 g = 34.32% of C3A leaf
- per-limb slice= C3A - C3C = 557,065 g = 26.22% of leaf = 76.40% of family
- flat slice    = C3C - C3B = 172,052 g = 8.10% of leaf = 23.60% of family
- check: 557,065 + 172,052 = 729,117 = family (exactly equal)
## Cross-base (vs nearest RAN anchor)
- vs r152b c98b: C3A -847 g; C3B -854 g (r152b 1,396,286); family +7 g (729,110 -> 729,117); ACIR invariant (609,966 both sides)
  -> #1996/I3 C3 base movement is effectively gate-neutral at the per-leaf level (leaf -0.04%);
     the table's C3 row migrates to 2,124,549 g (31.59% of the new pool DKG total 9,197,129 g;
     new pool family 2,849,526 g = 30.98%: -0.016 pts vs c98b).
- vs r147 old-d62e: flat slice identical (172,052 g; ACIR 224,942 at c98b and fold) -- base-invariant across #1996-era + I3;
  per-limb r147 966,604 g (at 2,966,353 leaf / 32.59%) -> fold 557,065 g. Note: different locus era (r147 pre-#1996, ACIR 1,087,267 leaf): the ~42% drop is mostly locus-era reshaping, not a flat-shape invariant;
  the r147 statement "<= 11 per-limb gate family pool" is unrevisable at this era (c98b per-limb was never RAN at f152b -- there was no C3C leg there).
## Credentials: legs used the shadow restitution protocol; peak is under 31 GiB (20.8 GiB max); workspace restored byte-exact; porch 0.
## Verdict: re-anchored. Fold-base C3 = 2,124,549 g, first durable per-limb/flat split on the folded tree; the -847 g C3A drift is #1996 locus reshape (I3 removed the raw-k1 push loop from the sponge) and is gate-neutral w.r.t. gate counts (ACIR identical);
  VERIFIED c98b..HEAD (git rev-parse blob compare, RAN): C0(pk.nr)/C1(pk_generation.nr)/C2a(ct0.nr)/C2b(ct1.nr)/C4(share_decryption.nr) all IDENTICAL; C3(share_encryption.nr) the ONLY leaf that moved. Hence the per-leaf table migrates exactly on the C3 row: DKG total 9,197,976 -> 9,197,129 (-847, all in C3), family pool 2,849,519 -> 2,849,526 (+7).
