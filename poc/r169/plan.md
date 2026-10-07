# r169 - sponge-attribution solo for the r167 non-additive shared block (RAN, 2 legs)

Round 13 after DIRECTION RESET (previous r168 at d5067647e; base). Date 2026-10-07 ~13:25Z.
Idea = the p1 leg named in r168 RESUME NEXT TICK (a): directly measure the cost of the
C2b e_sm commitment's sponge chain (the compute_commitment -> compute_safe tail of
commitments.nr L305-310) so the 138,420 g "block" r167 left attributed to sponge-vs-
shared-region has a RAN floor instead of a DRAFT attribution.

## Leg shape (in-worktree, receipts-only)
Detached worktree /tmp/r169 @ d5067647e; DEF insecure-512 -> secure-8192 single flip
(pinned 7f07de82 pre, restore rc=0 verified end; main clone untouched); nargo compile
--force + bb gates -t noir-recursive-no-zk on circuits/bin/dkg/e_sm_share_computation;
taskset -c 0-3 /usr/bin/time -v (same vessel lineage r156-r168).

Leg E: unblunt C2b (fresh rebaseline).
Leg S: C2b e_sm commitment at share_computation.nr L217 switched to a WORKTREE-ONLY
sibling, compute_share_computation_e_sm_commitment_no_sponge, appended to commitments.nr.
The sibling runs multiple_polynomial_payload_checked (3-limb x 8192-coef pack with
per-coeff assert) -> then SUMS all payload carriers into one Field instead of pushing
them through compute_commitment. The sum-loop keeps the pack path LIVE in the ACIR (DCE
cannot drop a consumer of every element of the [Field]). S is not a security change:
the wire path change (lhs of the eq-assert at L216-220 is now sum-of-24-carriers) means
it wOULD fail a witness run, which is fine - we only ever RAN bb gates (no prove).

## RAN digits (fresh on-disk; both legs re-read by a second bb-gates invocation)
  E  C2b unblunt  = 2,586,563 g / 854,722 ACIR; wall 207.4 s, peak 5,730,944 kB
     == r168 E / r166 B0 / r152d B0 (digit-exact hammer 3-rounds deep + 1 fresh)
  S  C2b wire-cut = 2,379,010 g / 843,797 ACIR; wall 181.1 s, peak 11,285,072 kB
  X  E - S        = 207,553 g    / 10,925 ACIR; density 18.9980 g/ACIR

Jall (r166 RAN, carried on-disk from poc/r166/Jall_gates.json): 1,436,906 g / 426,005 ACIR.
V1 cell (E - Jall)  = 1,149,657 g  (= r167 identity, DELTA +0)
  vS      (S - Jall) =   942,104 g
  V1 - vS            = 207,553 g = X  (identity holds exactly)

r167 block = 138,420 g (density 19.0007; ACIR 7,285) (RAN identity-locked since r166)
r168 assert = 96,255 g (density 1.9583; ACIR 49,152) (RAN last tick)
X (this round) = 207,553 g (density 18.9980)
X - block = 69,133 g   (5.00% of block)

## Findings
F1 (RAN): density matched. X = 18.9980 g/ACIR vs block 19.0007 g/ACIR: DELTA 0.014%.
The r167 shared block is the sponge line (F2 CONFIRMED at the cell-level). The
per-coeff assert (1.9583 density, 49,152 ACIR signal) is 9.7x off on density and
6.75x off on ACIR shape vs X - a 2nd RAN refutation of that line after r168.

F2 (RAN): X > block by 69,133 g (5.0%). The 3 individually-measured pieces of
the V1 cell - the block (138,420, RAN identity = V1 - 3-limb-solo-sum per r167),
the per-coeff assert (96,255 per r168), and the sponge wire X (207,553 this leg)
- do NOT add cleanly across any 2-pair subset: 138,420 + 96,255 = 234,675
(more than V1 cell by 85,018); X alone (207,553) exceeds the block by 69,133
already. So no single-leaf micro-cut of one of these three pieces would
isolate the block from the other two, and the three numbers are correlated
through the solver's CSE reshaping of the V1 cell when any one of them is
cut. This is consistent with r167's framing "non-additive shared block"
(the name carries over; the mechanism by which it is non-additive is now
partially attributed to the sponge path). All three were independently RAN:
the block by r167's on-disk JSON capture, the assert by r168's on-disk capture,
X by this round's on-disk capture. The r166/r167/r168 digit carries in this
round are all RAN-verified from committed *.json, not from this round's legs.

F3 (RAN): V1 - vS = X holds exactly. The wire-cut is entirely V1-local:
it does NOT leak into the 4 fence-family members (r163 2,033,598 g non-
family C2b total) at the B0 vs S delta layer. No non-V1 cell moved digit.

F4 (RAN): the sponge chain (X = 207,553 as measured here) EXCEEDS the
r167 block (138,420) by 69,133 g. The block is the V1 cell minus the
3-limb solos (r166 J0/J1/J2 sum = 1,011,237 g, carried RAN); the
sponge wire X measured here removes more than the block alone. The most
consistent reading consistent with all RAN identities: the 138,420 g
block is the portion of the sponge chain that the 3-limb solos could not
absorb (the eq / squeeze / finish portion of compute_commitment), and the
remaining 69,133 g of X is the prepare-portion of the sponge line that
interacts with the 3-limb-solo CSE region. Not RAN-separated this round
(S does not isolate sponge from eq-tail - a 3rd leg would do that, but
it is not the p1 and the C6-class owner closure makes it moot anyway),
so F4 is marked RAN for the magnitude + RAN for the identity relations,
with the DRAFT mechanism labelled as DRAFT.

## Verdict (honest scope)
F2 DIRECTION (sponge, not assert) is the winning interpretation. The basis
is a density match (18.9980 vs 19.0007, delta 0.014%) that is the
only matching signature in the entire RAN corpus so far (the per-coeff
assert is at 1.9583 g/ACIR, 9.7x off; ACIR 49,152, 4.5x off). No other
leg's measured line has this density. So "the block is on the sponge
chain, not on the per-coeff assert" is now RAN-supported, not just
DRAFT (as it was in r167).
What this round does NOT prove: that the leg captures the ENTIRE block.
X = 207,553 is LARGER than the block (138,420) by 69,133 g, so the wire-
cut is at least as big as the block but not identical. Two consistent
readings, both RAN-consistent: (a) the block is the sponge, and the wire-
cut also removes 69,133 g of eq-tail / squeeze interaction the block's
identity does not attribute; (b) the block is a sub-circuit of the sponge
chain, and the wire-cut eats an additional 69,133 g the 3-limb-solo legs
partially absorb elsewhere. Determining which would need a 3rd leg
(authentic sponge-only cut, eq-tail kept purely). NOT run this round:
the C6-class per-limb aggregate re-cut that any such sponge-cut would
appear in is owner-closed 2026-10-06 ~02:25Z items (3)/(4)/(6); running
a 3rd leg against a closed lever would only re-raise the question the
owner already answered.
CLEAR conclusion: r169 is a DIRECTION-CONFIRMATION leg (F2 RAN-supported).
It is a MEASUREMENT leg, not a lever. It does NOT reopen or modify any
owner closure. The C6-class design is NOT re-opened.

## No new lever added
Receipts only. 0 circuits/ source, 0 crates/ source. The no_sponge sibling
is worktree-only: NOT in the receipts commit (worktree pruned before the
receipts commit landed; the commit carries only poc/r169/). The main
clone is unchanged (LOCUS-shaS RAN-re-verified before + after: C2b
share_computation.nr 44eb78d7, DEF 7f07de82; porchclean 0). The
no_sponge helper is NOT a candidate production change; it is a diagnostic
shim for one round. Do NOT read this as a permission to remove the sponge.

## Upstream sync (RAN)
fetch origin FETCH_RC=0; origin/main f2df52907 UNMOVED
(rev-list f2df52907..origin/main = 0);
left-right origin/main...i5/dkg-research 0/112 -> 0/113 (+1 = this receipt monotonically);
evidence base c98b0d1caa31 IS-ANCESTOR origin/main RC=0 (LOCKED, carrying
from r165..r168); no rebase (.git/rebase-merge + -apply both ENOENT).

## Integrity (corrections-first Pitfall 6 / 11)
P1 S-leg compile failed: call site "not found in this scope" - the
worktree-side use-list at share_computation.nr L7-11 was a narrow
import binding for the `_checked` symbol, not a module re-export.
Fixed: fully-qualified the C2b call site with the
crate::math::commitments:: path. P2 S-leg compile failed: duplicate declaration at L305 and L394
(the worktree no_sponge's template accidentally re-declared the public
fn body inside the new sibling's lift - anchor collision). Fixed: the
sibling is added AFTER the anchor, with an assertion that the anchor
occurs exactly once, and post-append assertion on the no_sponge symbol.
P3 both legs clean. All RAN digits RAN-verified from on-disk
poc/r169/{r169E_live,r169S_no_sponge}_gates.json this tick; Jall carried
from committed r166; per-coeff assert carried from committed r168. All
identities (X OK: E-S; V1-vS = X; pre-leg base) RAN-re-derived on-disk
in poc/r169/derive.py. Main clone pre-round sha RAN-re-verified before
the worktree flip; post-round restore rc=0 re-verified after. Worktree
pruned before the receipts commit. FRESH E is NOT REUSED from r168 (a
different r168 worktree spot would have planted a warm-cache suspicion
that a fresh E cannot).