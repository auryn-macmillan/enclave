# r164 - C2b non-family (B) block decomposition @ fold tip cb722eea281

R163 RAN the C2b family (check_range_bounds step 3) = 552,965 g, 100% per-limb, flat 0
(B==C digit-exact). R163's B leg (whole check_range_bounds fn NOP) = 2,033,598 g = E1 - family
= the NON-family remainder of the C2b leaf. This round decomposes that remainder into the 4
machinery blocks C2b execute() (share_computation.nr L172-187) runs OUTSIDE step 3:

  V1  verify_secret_commitment  (SmudgingNoiseShareComputation impl, L200-221, unit ret)
      commits [Polynomial<N>;L] = 3x 57-bit e_sm polynomials (C2a's twin commits 1x 1-bit sk)
  V2  verify_secret_consistency (SmudgingNoiseShareComputation impl, L235-245, unit ret)
  V4  verify_parity_check       (free fn, L290-313, unit ret)
  V5  commit_to_party_shares    (free fn, L319-341, RETURNS [[Field;L];N_PARTIES])

Only V1 differs between the C2a and C2b twins => structural prior: V1 carries the twin gap
(C2b-B 2,033,598 minus C2a-B 911,778 = 1,121,820 g).

## Method

Detached worktree /tmp/r164 @ cb722eea281 (main clone untouched; pruned after the round).
r163-style shadow-NOP harness: secure-8192 preset flip in configs/default/mod.nr (insecure->secure
dkg+threshold); one block solo-NOP'd per leg, all other 3 blocks + the family stay live; DEF 7f07de82
+ SC 44eb78d7 sha-pinned before and restored byte-exact after every leg (trap + post-round verify;
worktree final tracked diff = 0). V5 returns [[Field;L];N_PARTIES] so its NOP appends a valid zero
return [[0; L]; N_PARTIES]. Vessel: per-leg taskset -c 0-3 + /usr/bin/time -v; nargo compile --force;
bb gates -t noir-recursive-no-zk. Splice = comment the brace-counted body of the N-th matching fn
(header search for V1/V2 anchored on the SmudgingNoiseShareComputation impl so it cannot hit the C2a
twin; dry-tested in isolation before the run: all 4 splice balance-checked, V1/V2 verified to touch
e_sm_secret not sk_secret, N=2 for the two impl methods, N=1 for the two free fns).

## RAN (fold tip cb722eea281; digits from on-disk *_gates.json)

  E1  C2b unblunt            = 2,586,563 g   ACIR 854,722   (r163/r152d/r158E golden, delta 0, cross-base
                                                         stability holds at the fold tip)
  V1  s1 solo NOP            = 1,436,905 g   ACIR 426,004
  V2  s2 solo NOP            = 2,561,987 g   ACIR 830,146
  V4  parity solo NOP        = 2,377,667 g   ACIR 707,266
  V5  party solo NOP         = 1,938,913 g   ACIR 821,943

## DECOMPOSITION (RAN; block_i = E1 - leg_i; family = r163 RAN)

  family (r163)  =   552,965 g   (27.19% of B)
  V1  s1  commit  = 1,149,658 g   (56.53% of B)
  V5  party commit=   647,650 g   (31.85% of B)
  V4  parity      =   208,896 g   (10.27% of B)
  V2  s2  consist =    24,576 g   ( 1.21% of B)   = 8192 x 3 (N x L) exactly
  sum(V1,V2,V4,V5)= 2,030,780 g   vs B 2,033,598 -> gap -2,818 g (-0.14%), r161-class small solver
                 non-additivity (under 0.2%; blocks treat as additive for modelling)

## VERDICT / MODEL RULE

1. The C2b twin gap 1,121,820 g localizes to the NON-FAMILY 4-block sum (V1+V2+V4+V5 = 2,030,780
   vs C2a-B 911,778); the family is byte-twin-invariant (r152d/r158/r163, delta 0 both bases), so
   the gap is 100% non-family. V1 = 1,149,658 g = 102.5% of the twin gap: V1 over-explains by
   +27,838 g, consistent with the r161-class per-loop solver-CSE overlap (the 4-block sum is below
   B by 2,818 g, and V4+V2 share the y witness with V1). The RAN upper attributable mass on C2b
   is 1,149,658 g (V1's solo cost).
2. Model rule (load-bearing): any FUTURE C2b-vs-C2a per-limb aggregate lever binds down to the
   V1 commit surface - 3x 57-bit e_sm limb commits (C2b) vs 1x 1-bit sk commit (C2a). V5 (31.85%)
   and V4 (10.27%) + V2 (1.21%) are common/shared machinery and cancel out of the twin-difference;
   the only C2b-specific levers at this shape are V1 commit count or V1 commit width.
3. NO NEW LEVER (0 source change; 0 circuits/ + 0 crates/ delta). The C6-class per-limb
   aggregate redesign stays CLOSED per the 2026-10-06 owner closure line; this round adds a
   sharper RAN attribution (V1 = 56.53% of C2b non-family; V1 = 102.5% of the twin gap) that any
   future owner-gated re-opening consumes directly.

## INTEGRITY (corrections-first, Pitfall 11)

E1 golden-digit re-confirmed at fold tip (delta 0 vs r163). All 5 legs first-attempt success
(no splice/solver fault; 5/5 landed, no harness correction). Worktree rc-0 final with byte-exact
restore (SC 44eb78d7 + DEF 7f07de82 re-verified after the run; main-clone tracked diff 0; only the
untracked poc/r164 receipts remain; /tmp/r164 worktree pruned). Localization numbers all derived
from the on-disk *_gates.json caption digits by python this round (no memory recompute): the
56.53/31.85/10.27/1.21 % figures and the 102.5%-of-twin-gap ratio all checked a second time in a
separate recon before being written into STATE.md / the digest.