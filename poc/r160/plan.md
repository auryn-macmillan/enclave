r160 - C3 flat deep-slice: the message range check solo, on the unblunt basis @ fold tip 733eb45ae

Idea (per r159 RESUME RULE, p1 = C3 flat deep-slice): the C3 flat slice (172,052 g = 23.60% of the
family, r156 RAN) has never been decomposed into its cells. r159 did the same for the C1 flat
(e_sm_lifted solo 127,023 g = 62.4% of the C1 flat). This round singles out the one widest flat
call, `self.message.range_check_standard::<BIT_MSG>` (BIT_MSG = 59; the other three flats are u = 1
bit, e0 = 5, e1 = 5), NOPping just that call on the unblunt basis, and measures its sole cost.
The three narrow flat polys are then pinned by subtraction from the r156 digit-locked flat.

Why digit-carrying r156 A/B/C is safe here: the C3 locus blob is byte-frozen 7e999546e (the r156
leg base) -> 733eb45ae (the fold tip; this round's leg base), git blob hash a38431229 at both
commits, RAN-verified this round (`git rev-parse <sha>:circuits/lib/src/core/dkg/share_encryption.nr`
== at both, reading back a384312297fe7b190e760f77a1af727aaa328a62). The DEF blob git hash 76bfde23
is likewise identical; the worktree content happens to be sha 308c8c5d (SE) / 7f07de82 (DEF), both
RAN-pinned in the leg script's preflight. Therefore r156's A/B/C (2,124,549 / 1,395,432 / 1,567,484)
digit-carry onto this base; only the fresh M leg is RAN here.

Leg design (shadow NOP, r156/r157/r159 lineage):
  M  comment-block the one-line message.range_check_standard::<BIT_MSG> call; leave the u/e0/e1
     flat checks and all 4 per-limb-loop checks live. One-line splice; python asserts before compile:
     one sentinel, brace balance, and all 7 other range calls still present.

Vessel: detached worktree /tmp/r160 @ 733eb45ae (main clone untouched, worktree pruned after the
leg; pruned state RAN-verified at end of round). secure-8192 flip in configs/default/mod.nr (the
PRE_DEF/PRE_SE pins are content-SHA based; the flip rewrites the two preset lines + the header).
Artifact at the package-root target dir circuits/bin/dkg/target/share_encryption.json (r152b vessel
note); bb gates -t noir-recursive-no-zk; in-session foreground + taskset -c 0-3 + /usr/bin/time -v
(r156/r157/r159 precedent on this box: the background-scratch variant dies on auto-reap, see r159).

RAN (fold tip 733eb45ae):
  M  message solo NOP (u/e0/e1 + 4 limb checks + quotient stay live)
     = 2,063,109 g   ACIR 585,390   wall 223.8 s   peak 19,013,892 kB (18.1 GiB)
  Identity cross-check: `bb gates` independent re-read of M gates == 2,063,109 (RAN).

DECOMPOSITION (RAN; identity holds exactly):
  message solo (this round's new digit) = A1 - M = 2,124,549 - 2,063,109 = 61,440 g = 2.89% of leaf = 35.71% of C3 flat
  u + e0 + e1  = r156 flat (172,052) - message (61,440) = 110,612 g = 5.21% of leaf = 64.29% of flat
  identity             = 61,440 + 110,612 = 172,052 == r156 flat   (delta +0)
  family identity      = 557,065 (per-limb, r156) + 61,440 (message, r160) + 110,612 (u+e0+e1, r160)
                       = 729,117 == r156 family   (delta +0)

COST-OBSERVATION (the interesting direction, RAN): the three NARROW flat polys (1/5/5-bit
`range_check_2bounds`) pack a combined 110,612 g, ~1.8x the cost of the single 59-bit
`range_check_standard` message check, despite each of the three bounding far less bitwidth than
the message. Cross-check at hand: C1 e_sm_lifted 147-bit 2bounds solo = 127,023 g (r159 RAN) vs
these three narrow 2bounds polys = 110,612 g combined -- the single 147-bit cell costs only ~15%
MORE than all three narrow polys combined. If cost scaled roughly with checked bitwidth per poly,
147 bits vs (1+5+5) bits total would predict far more than a 1.15x cost ratio. The most defensible
RAN reading: in this era, flavor of the range-check gadget dominates width - a near-fixed
per-poly/per-coefficient term, not a bit-width-proportional one. Supporting RAN datapoint: on the
message leg the gate delta (61,440) and ACIR delta (609,966 - 585,390 = 24,576 = 3.00 ACIR per
coefficient on the 8192-coef message poly) are both commensurate with a small constant cost per
coefficient. This is a FINDING only (two datapoints), not a verdict: discriminating width-linear
from fixed-cost needs the u/e0/e1 solo legs (the NEXT-tick p1).

The 23.60% flat is NOT a miscolor of the per-limb span (confirmed by the leg design: the flat is
the sum of exactly the 4 above-loop cells; the round's family identity per-limb + message +
u+e0+e1 = A1 - B holds at digit 0). C3's flat splits into message 35.71% / u+e0+e1 64.29%; the
latter is still 3 separate polys not solo-isolated (u/e0/e1 solo = the 3-leg follow-up above; the
110,612 g split is RAN-by-subtraction from the r156 flat, not from three fresh legs).

EQUIVALENCE (no new lever added, no gate change): this is a sibling to r159's C1-flat cell
finalization. With C3's flat split complete, the fold-base DKG table is now fully sliced to cells
for C1 (r157/159), C3 (r156/160), and C2a (r158). C2b remains at its family layer (100% per-limb
predicted by r152d twin, NOT RAN); C0/C4 have empty family. Table is now closed to the level of
cells for every row that has a flat.

NEXT tick (a few more legs, RAN-eligible, same envelope): the p1 pick = **u/e0/e1 solo legs**
-- solo-RAN each of the 3 narrow flat polys in a single worktree round, 3 legs ~65 min total --
and see if the 110,612 g splits by width (1:5:5 if bit-width-linear, ~1:1:1 if fixed-cost-
dominant). That test is the discriminator for the cost-observation above. Secondary: C2b
per-limb/flat RAN (closes the table at the twin row). Owner closures apply: (3) C4-consumer
acc-pin, (4) LIVE-NETLINK, (6) box-2 secure-8192 all CLOSED -- do NOT advance, source-edit, or
re-gate.

INTEGRITY (corrections-first): single leg; the only fresh RAN number in this document is M
= 2,063,109 g / ACIR 585,390, re-verified by an independent `bb gates` re-read of the on-disk
r160M_msg_solo_gates.json (byte-match). A1/B/C are r156 RAN pin numbers, quoted from
poc/r156/C3{A_live,B_full,C_limb}.r156 (r156 leg base 7e999546e; carried to 733eb45ae via the
blob-frozen equality RAN-verified above). The "147-bit 127,023 g vs narrow 3-poly 110,612 g" cross
comparison is RAN-derived from r159 (127,023 g digit-locked in poc/r159/ receipts) and this round
(110,612 g = RAN 172,052 - RAN 61,440). LOCUS/DEF byte-restored after leg M (restore rc=0, both
content-SHAs re-pinned); the worktree left no modified files (leg-script sentinel asserted
PORC_NONUNTRACKED=0 and the ran output reported R160_STATUS=OK); the worktree was pruned after the
round.

Confab audit before persist: the constants in this plan (61,440 / 110,612 / 172,052 / 61,440+110,612
= 172,052 / 557,065 / 729,117 / 585,390 / 609,966 / 24,576 / 3.0) were each re-verified against
poc/r160/*.r160 and r156 digit sources this round; governing SHAs 733eb45ae (HEAD), a38431229
(C3 blob git hash, RAN), 76bfde23 (DEF blob git hash, RAN), 308c8c5d (SE content SHA, RAN), c98b0d1c
(EB, is-ancestor RAN rc 0) were re-verified this round. No other constant is carried from memory.

UPSTREAM SYNC (RAN): git fetch origin FETCH_RC=0; origin/main f2df52907 UNMOVED (rev-list
f2df52907..origin/main = 0; left-right origin/main...HEAD = 0/102). EB c98b0d1caa31 LOCKED in
origin/main (is-ancestor rc 0). No rebase needed.

UPSTREAM-PR: none (0 circuits/ source change; only poc/ receipt + plan + the leg script).