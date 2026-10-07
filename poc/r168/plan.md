# r168 - per-coefficient assert cost leg (F2-attribution, RAN)

Date: 2026-10-07 ~13:30 UTC. Round after r167 (2a17cadce), post DIRECTION RESET.

## Idea (the single p1 picked this round)
r167 RESUME NEXT TICK (c): "target only the assert_max_bit_size::<...> at helpers.nr
L89 on limb 0 via a 'disable per-coefficient assert' leg; if it runs green, RAN-splits
the 138,420 g block into 'shared absorb' [SOLO] vs 'fixed pack loop' [residue]."
Reframed while building (see Findings (3)): the raw per-coeff assert is NOT one limb's
span, it is the summed assert across ALL 3 limbs of the e_sm pack tail, so a whole-c2b
leg (not a limb-0 leg) is the correct isolation. That is what this round runs.

## Status: RAN (2 legs, fresh this tick)
Leg E (C2b unblunt, secure-8192): 2,586,563 g / 854,722 ACIR, wall 213.0 s, peak 5,737,392 kB.
  -> digit-exact vs r166/r152d B0 golden (2,586,563 / 854,722); a 2nd independent bb gates
     re-read of the fresh.json matched.
Leg F (same leaf, per-coeff assert disabled): 2,490,308 g / 805,570 ACIR, wall 211.9 s,
  peak 5,703,280 kB -> independent bb re-read matched.
DELTA (E-F) = 96,255 g / 49,152 ACIR.

## Method (receipts-only, 0 circuits/ + 0 crates/ source committed)
- Detached worktree /tmp/r168 @ 2a17cadce (pruned after). Main clone never touched.
- flip DEF insecure-512 -> secure-8192 once (configs/default/mod.nr); the flip is NOT
  in any commit (restore byte-exact 7f07de82 at end, RAN-verified main clone clean).
- Leg E: nargo compile --force on circuits/bin/dkg/e_sm_share_computation (artifact at
  package-root target/e_sm_share_computation.json), then bb gates -t noir-recursive-no-zk.
- Leg F: splice helpers.nr L88-89 (the per-coeff injectivity-assert line) to a comment
  ("F-NOP r168"), DEF still secure-8192, same compile+gates. Splice unique-match
  asserted (count==1); brace balance asserted; verified F-NOP applied before compile.
- Capture wall+peak via taskset -c 0-3 /usr/bin/time -v. Byte-exact restore + porcelain 0.
- Merge the working tree with the RAN python3 arithmetic recheck (on-disk r166 carries
  + LEG F this-tick numbers -> derive-style delta, all RAN).

## Source premise (RAN read this tick)
- The e_sm limb frame is L=3, N=8192 (r167 RAN-source close); the per-coefficient
  assert lives at helpers.nr L89 inside pack_checked (L71-100), which flatten_checked
  (L104-115) calls once per CRT limb, and multiple_polynomial_payload_checked
  (commitments.nr L181-186) calls for the C2b e_sm commitment. So NOP-ing L89 removes
  the injectivity assert for all 3 limbs x 8192 coeff = 24,576 coefficients at once.
- ACIR arithmetic checks out: DELTA ACIR = 49,152 = 2 x 24,576 exactly -> that assert
  lowers to exactly 2 ACIR opcodes per coefficient (matches a 1-sided
  assert_max_bit_size pattern the backend uses).

## Findings (RAN; the load-bearing ones)
(1) The per-coefficient injectivity assert at pack_checked L89 carries 96,255 g =
    3.7213% of the full C2b leaf (unblunt basis). It is real and non-negligible.
(2) DENSITY-DISCRIMINATION (the point of the round): the r167 non-additive shared
    block is 19.0007 g/ACIR; the assert measured here is 1.9583 g/ACIR = 9.703x LESS
    dense, and its ACIR signature is 49,152 (2.0000/coeff) vs the block's 7,285.
    => the per-coeff assert is NOT the dominant cost of the 138,420 g block.
(3) r167 p1/c hypothesis is REFUTED: "leg the assert to RAN-split the 138,420 g block
    into absorb-vs-pack" fails because the ACIR signatures differ by 6.7x. In raw g the
    96,255 overlaps 69.5% of 138,420, but the ACIR mismatch rules squeezing them to the
    same object: block = 138,420 g with only 7,285 ACIR (high-gate / low-opcode terrain,
    i.e. absorb/sponge-style), assert = 96,255 g with 49,152 ACIR (low-density per-coeff).
    NOTE: absolute-g overlap (69.5%) is NOT a free identification; the ACIR signature
    is the discriminator and it does NOT match.
(4) F2/DRAFT (r167 sponge-attribution) STAYS OPEN as the only remaining path for the
    138,420 g block (edges toward compute_commitment/compute_safe helpers.nr L245-252
    + commitments.nr L122-124). A further 1-leg sponge solo would be the next test.

## No new lever added
This is a measurement + REFUTATION round. The r167 p1/c idea is closed (REFUTED); the
C6-class per-limb / shared-block redesign closure (2026-10-06 owner close (3)/(4)/(6))
remains in force. No source committed. No source kill, no new lever, no commit gate.

## Upstream sync (RAN)
fetch rc 0; origin/main f2df52907 UNMOVED (rev-list f2df52907..origin/main = 0); left-right
origin/main...HEAD = 0/111 (r167 was 0/110, +1 = this receipt); NO_REBASE dirs ENOENT;
EB c98b0d1caa31 LOCKED (is-ancestor rc 0).

## Integrity (Pitfall-6/11)
Transport degraded 2 plan-md drafts (spurious "acron-style", "dc0", "diskacic",
"3-limb-soils", "7e98854" tokens); all caught by a whole-file garble + non-ASCII scan
before any commit, rewritten from live re-verified digits. Every RAN number in this
receipt is pulled this tick from poc/r168/*_gates.json (2 legs), bb gates JSONs carried
from r166 (5 legs) or derive.out from r167 (reference). No number from memory.
Restore verified: main clone sha256 44eb78d7 (C2) / 7f07de82 (DEF) / 0 circuits/ 0
crates/ change; worktree pruned; parent-container = 2a17cadce.

## Mutations
- ONE receipts-only commit on i5/dkg-research (poc/r168/).
- Review branch research/r168-per-coeff-assert-cost pushed to enclave (new ref; no rewrite).
- STATE.md head-block replacement (single-anchor, count==1); LOG.md dated entry appended.
- Verify-after: `rev-parse --verify` on new ref, `ls-remote --heads origin | wc -l`, sha-scan,
  full-tree porcelain 0, C2+DEF sha pin stable, NEW leg's shadow-NOP does NOT hit main clone.