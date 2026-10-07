# R165 - C2a per-block decomposition @ fold tip; closes the C2b<->C2a twin-gap to a digit.

**Goal (p1 per r164 RESUME NEXT TICK):** measure the C2a-side V1 (sk-commit) and V2 (sk
consistency) cells at the fold tip so that the C2b-minus-C2a twin gap
(1,121,820 g = r163/r164's (C2b-B) - (C2a-B) RAN figure) can be attributed exactly.
r164 measured the C2b side: V1b 1,149,658 g (3x 57-bit e_sm limb commitments)
and V2b 24,576 g (= N x L); it flagged that r164's "V1 over-explains the twin gap
by +27,838 g (2.5%)" was a prediction, not a measurement because the C2a V1 cell
had not been RAN-anchored.

**Upstream (RAN):** origin/main f2df52907 UNMOVED (rev-list f2df52907..origin/main = 0).
No rebase. Evidence base c98b0d1caa31 LOCKED (is-ancestor rc 0). Head moved from
headers r163 (a5d563249 -> cb722eea2 -> 3dbb164 receipt-only chain, HEAD this tick
= 3dbb164cdbd).

**Method:** detached worktree /tmp/r165 @ 3dbb164 (main clone untouched, pruned
after round). preset flip in `circuits/lib/src/configs/default/mod.nr`
(7f07de82 -> secure-8192) performed once before the first compile and held across
leg calls; SC (`circuits/lib/src/core/dkg/share_computation.nr`, pinned 44eb78d7)
spliced in place per leg: 1st occurrence of `fn verify_secret_commitment` = C2a
V1a (1x 1-bit sk_commit w/ reversed_coeffs normalization); 1st occurrence of
`fn verify_secret_consistency` = C2a V2a; the free fns (parity / party-commit)
stay IDENTICAL between twins (shared locus) so r164's C2b-leaf RAN legs V4b / V5b
carry to C2a for the twin-differential WITHOUT re-running. Trailing python
block recomputes every derived number on-disk from the *_gates.json files before
the durable writes are spliced in.

**Legs (4 RAN this round, in-session foreground, taskset -c 0-3 + /usr/bin/time -v,
peak <= 5.7 GiB << box 32 GiB, no OOM):**

```
A   C2a unblunt (LOC unedited, DEF secure-8192)          = 1,464,743 g  ACIR n/a
    (r152d / r158 golden 1,464,743 g, delta +0 RAN-confirmed at fold)
V1A C2a V1 solo (1x 1-bit sk commit NOP)                 = 1,436,905 g  ACIR 426,004
V2A C2a V2 solo (1x sk consistency NOP)                  = 1,440,167 g  ACIR n/a
E   C2b unblunt sanity (LOC unedited)                    = 2,586,563 g  ACIR n/a
    (r164 E1b golden 2,586,563 g, delta +0 RAN-confirmed)
```

r164 carries (digit-anchored to the same fold tip, reused as C2b-side legs):
E1b 2,586,563 g | V1b 1,436,905 g (ACIR 426,004) | V2b 2,561,987 g |
V4b 2,377,667 g | V5b 1,938,913 g.

**Cells (leaf - solo leg):**
C2a V1 = 1,464,743 - 1,436,905 = **27,838 g**        (1x 1-bit sk commitment)
C2a V2 = 1,464,743 - 1,440,167 = **24,576 g**       (= 8192 x 3 = N x L)
C2b V1 = 2,586,563 - 1,436,905 = **1,149,658 g**   (3x 57-bit e_sm limb commitments)
C2b V2 = 2,586,563 - 2,561,987 = **24,576 g**       (= 8192 x 3 = N x L)

**Twin-gap decomposition (RAN, on-disk-derived):**
Twin gap (E - A)  = 2,586,563 - 1,464,743 = **1,121,820 g**
dV1 (C2b V1 - C2a V1) = 1,149,658 - 27,838 = **1,121,820 g**  (= 100.00% of the twin gap)
dV2 (C2b V2 - C2a V2) = 24,576 - 24,576    = **0 g**           (= 0.00% of the twin gap)
(dV1 + dV2)                       = 1,121,820 g   residual = E - A - (dV1 + dV2) = **0 g** EXACT

**SIGNATURE RESULT (RAN cross-leaf invariance):** the V1-solo leg landed digit-identically on
both twins: C2a V1A = 1,436,905 g / ACIR 426,004 vs C2b V1b = 1,436,905 g / ACIR 426,004.
Delta on again + ACIR = 0 between the two legs. Consequence: everything OUTSIDE the V1
block (V2 + family + parity + party-commit) is gate- AND opcode-identical between C2a
and C2b. The whole C2b-minus-C2a twin gap lives in the V1 block.

**Load-bearing number for any future re-opening:** the C2a V1 cell (27,838 g) is exactly what
r164 had flagged as the unresolved +27,838 g. With C2a V1 now RAN-anchored, the twin-gap
attribution is **100.00% V1** (previously predicted 102.5%). The joint-lattice fringe that
r164 left as an open ~2.5% is 0 in the twin differential because the V2 consistency cell
is gate-identical (both leaves use y[i][j][0] == sk_secret[i] with the same loop shape,
N x L = 8192 x 3 = 24,576 g of equality checks, digit-identical across twins).

**MODEL RULE:** for any C2a/C2b redesign, the load-bearing surface is the V1 commitment
object alone (3x 57-bit e_sm limb commitments on the C2b path vs 1x 1-bit sk on the C2a
path; family / V2 / V4 / V5 are byte-shared and cancel). Any lever that touches V5 / V4 /
V2 expecting twin-gap relief is dead (both twins get the same cost).

**No source change, no circuits/ or crates/ delta -> receipts-only commit + review branch.**
UPSTREAM-PR: NONE.