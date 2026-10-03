# r150 - C4 range-family ABSENCE (RAN kill-round; DONE unvetted -> poc_done)

Date 2026-10-03 UTC. r150 = the DIRECTION 2026-10-02 queue's "r150 = C4 range-family
shadow-NOP." The item was flagged twice in prior state (r145 + r149 NEXT rows) as "the last
UNPRICED leaf = OPEN non-gated item: C4 (15.11% of DKG base); r141's dense-rate RAN covers
C4's per-coeff checks at a different shape point."

## PREMISE KILL AT SOURCE (before any build)

The premise read by r145/r149 is FALSE at source. Direct source inspection of
`circuits/lib/src/core/dkg/share_decryption.nr` (170 lines, C4a + C4b, on-disk sha
ca9a76dec... byte-stable after r149) shows `ShareDecryption::execute(moduli)` calls exactly:

    self.verify_commitments();
    let aggregated = self.compute_aggregated_shares();
    let normalized = normalize_aggregated::<N, L>(aggregated, moduli);
    compute_aggregated_shares_commitment::<N, L, BIT_AGG>(normalized)

Component families actually in the C4 cone (body-scoped grep on the EXACT functions C4
calls, not file-wide counts):

  SYMBOL                                                      range_check_* bodies
  --------------------------------------------------------    --------------------
  ShareDecryption leaf (share_decryption.nr, all 170 lines)   0
  compute_share_encryption_commitment_from_message            0
  compute_aggregated_shares_commitment                        0
  ModU64::reduce_mod                                          0
  Polynomial::new (constructor)                               0
  SafeSponge (state/pathway; all constraints via Assert)     0

Consequently the "C4's per-coefficient 58-bit range family" that r145/r149 queued as a
shadow-compile target **does not exist**. The `check_range_bounds<...>` function in
`share_computation.nr:245` is called from C2a (`SecretKeyShareComputation::execute:102`)
and C2b (`SmudgingNoiseShareComputation::execute:172`) -- not from C4. C4's 1,746,030 g
(15.11% of the 11,558,499 g min-base DKG-leaf family) are SAFE-sponge + unconstrained
CRT-sum aggregation + ModU64::reduce_mod + centered-branch, NOT a per-limb or flat range
family. There is no B-leg (full-NOP) or C-leg (per-limb-slice) anchor, because there is no
range function to comment out.

CONTRAST (body-scoped grep confirms the same tool reads correctly on a leaf that DOES
have range calls):

  C1  pk_generation.nr        perform_range_checks  body-only hits:   5
  C2  share_computation.nr    check_range_bounds    body-only hits:   2
  C3  share_encryption.nr     check_range_bounds    body-only hits:  10
  C4  share_decryption.nr     (no range calls)      body-only hits:   0

## RAN UNBLUNT RE-ANCHOR (B-pin at the current tip of i5/dkg-research on d62e22e)

Working branch i5/dkg-research @ 936d357f6 (r149 tip). Base origin/main d62e22e16
UNMOVED (REBASE no-op; RAN fetch RC 0; merge-base == origin/main == HEAD base; 92
ahead / 0 behind). Round runs at HEAD.

Box 8c / 31 GiB / 0 swap (re-provision 2026-09-11; RAN pre-leg: nproc 8, MemAvailable
30 GiB, load1 0.16). systemd user unit r150_a_rangel_a.service, MemoryMax=31G, taskset 0-3
(@4c pin per r99/r100/r101/r145/r149 legacy policy), nargo 1.0.0-beta.26 / bb 5.1.0.

  LEG   circuit                 gates       ACIR      wall       peak           Swaps  FRESH_SHA256
  ----  --------                -----       ----      ------     --------------  -----  ----------
  C4A   dkg/share_decryption  1,746,030   573,457   1:53.78    4,352,900 kB    0       1c417a0209b13de94d4eff8ec8f5bb7298aee62b5fa0228c145d81bcde3855a2

DIGIT-EXACT r45/r46/r48/r75/r101 golden 1,746,030 gates (15.11% of the DKG-leaf 11,558,499 g
min base; diff 0). Era drift vs r46 peak = 4,352,900 kB / 4,373,972 kB = 0.9952x (r99/r100/
r101 no-uplift class: the min point is RAM-size-bound not core-parallel-bound, so the 4c vs 8c
width does not move it -- same effect class the r45/r100/r101 byte-pin proves has no shape drift
across toolchain eras).

Preservation RAN:

  in-tree bin/target share_decryption.json pre-leg sha  ace53e15f44d5f334379303a6e6ffde56b10bd480ee53e7474f5ee759a105b3d8f3d2f  (see poc/r150/restore_check.txt)
    -- NOT  modified by r150 (no source edit to the C4 leaf; only the transient insecure->secure-8192
       preset flip in configs/default/mod.nr + configs/committee/active.nr, restored byte-exact below)
  DEF   7f07de82407c9601dd737044af69a068238dd9ff175f51c4d64d8e00980aa207  byte-exact
  ACT   0bf0cc642ddfa98d48f51f7d007dc6749e9c1d4b4b02c36d9e1da1d4735d0ac4  byte-exact
  SD    ca9a76decc678ca465e60e616dc7c7e3bb3275c4b50e4360a0c4124793724234  byte-exact (never edited)
  git status --porcelain after-leg = '?? poc/r150/' only (this round's tree; nothing in-tree dirtied)

## LEAF PRICE TABLE POST-r150 (all leaves priced, killed, or ruled out in prior rounds)

  leaf   min gates   %DKG    range-family % of leaf      range-family %DKG    status
  ----   ----      ---     ----     ---- --------------  ---- ---     ---- --------------
  C0      287,727   2.49%    UNPRICED-but-non-lever (C0 = pure-leaf, has no range family per r45/r99 pin)  --
  C1    2,223,114  19.23%    39.92% leaf = 887,460 g    7.68% DKG            r149 DONE
  C2a   1,446,311  12.51%    38.23% leaf = 552,965 g    4.78% DKG            r145 DONE (tag r34: load-bearing)
  C2b   2,888,964  24.99%    19.14% leaf = 552,965 g    4.78% DKG            r146 DONE (class RAN-confirmed twin of C2a)
  C3    2,966,353  25.66%    38.38% leaf = 1,138,656 g  9.85% DKG            r146 DONE (per-limb r147 = 8.36% DKG)
  C4    1,746,030  15.11%    NO RANGE FAMILY ----------------------------    r150 RAN-KILLED (this round)
  ----------------------------------------------------------------------------
  Total  11,558,499  100%    --------   --------   --------   --------

C4 IS NOT CHARGEABLE-BY-FAMILY. Its 15.11% share of the DKG-leaf min-base is a middle-of-pack
footprint (4c envelope for the RAN-anchored secure-8192/min card: r99 + r100 + r101 = 12.01 /
10.59 / 12.82 GiB @4c; r124/r125/r126 fix the r101-class ceiling against the current
31 GiB box). The RAN structural block: it has no per-limb nor flat range family to cut.
The per-limb source-editing lever C3 proved works (r147 = 966,604 g = 8.36% DKG RAN) does NOT
apply to C4 for the structural reason proven in the source table above.

## CHANGES TO THE r145 RANKING (drop the dense-rate C4 line; family + RAN only)

Prior run-by-run (r145 -> r146 -> r147 -> r149):
  1 C3  9.85% DKG (r146 RAN)  2 C1 (19.23% leaf, UNPRICED)  3 C2b  4.78% DKG (r146 RAN)
  4 C2a  4.78% DKG (r145 RAN)  5 C4 (dense-rate "unpriced leaf" -- this item is in ERROR)  6 P3 leftover

Re-examining r145: r145's r141 dense-rate line for C4 was an anchor, not a family. The r141 4-
cell sweep ran on a C4 *base* shape at a different shape point, NOT the actual C4-leaf cone. Its
production path (A + B + C 3 legs) has 0 range_check invocations -- the 4-cell dense-rate
recording was a local computation, not an extractable + reducible family. Under r150's source-
tree evidence this row lands as RAN-killed, NOT "the last unpriced leaf."

Family-percent ranking (RAN inputs only):

  1  C3   9.85% DKG  (r147 RAN; largest RAN component family, is the (0)-winner)
  2  C1   7.68% DKG  (r149 RAN)
  3  C2b  4.78% DKG  (r146 RAN; twins with C2a)
  4  C2a  4.78% DKG  (r145 RAN; r34 load-bearing tag)
  5  C4   NOT IN SET (r150 RAN kill: no range family)
  6  P3 leftover   < 3.8% of r132 cell  (browser-side; two families: SAFE-sponge 96.18% + payload 3.82%)

CONSEQUENCE: the per-limb spec-A (0)-winner (C3 = 9.85% DKG, r147 RAN price) is already priced
and owner-gated (item (5), C6-class in-tree modifier round). r150 does not unroll that gate; it
closes the last open per-limb price queue. The correction to r149's "NEXT = C4" is: discard it.
The in-tree lever r147 found for C3 is the strongest RAN family in the DKG-leaf tree -- it does
not launch automatically. Gate continues with per-diff re-authorization.

## VERDICT

RAN KILL. C4, queued as "the last UNPRICED leaf, 15.11% of DKG", is disproved at source.
C4's 1,746,030 secure-8192/min gates contain no per-coefficient, no per-limb, no flat range
family slice. The DIRECTION block's per-limb queue is now FULLY priced (r145 + r146 + r147 +
r149 + r150). The next non-gated actionable lever is outside the per-limb range-family class:
it sits on the SAFE-sponge bodies (r132 RAN -- 96.2% of the M3 browser-cell cell; browser-side,
not the current DKG-hours target), the ModU64::reduce_mod blocks (no prior round has thrown
at them; RAN-unpriced; DRAFT on box-2 if the owner directs), or the <3.8% residual of the P3
browser cell.

## RUN COMMANDS

RAN unblunt (reproducible, ~2 min wall @4c-pinned):
  (on this box, with repo pinned to i5/dkg-research @ 936d357f6)
  systemctl --user daemon-reload
  systemctl --user start r150_a_rangel_a.service
  # then: systemctl --user stop r150_a_rangel_a.service
  # outputs under poc/r150/ (C4A.r150, C4A_gates_raw.json, source_audit_v2.txt)

RAN source audit v2 (independent of compile; idempotent; ~0.1 s):
  bash /home/dev/interfold-research/interfold/poc/r150/source_audit.sh

## SHIP / NOT SHIP / UPSTREAM-PR

- Not a sound vehicle. All prior rounds' shadow-NOP legs are measurement-only per protocol;
  r150's in-tree change = none (impossible to bleed). Only .nr config flip + restore.
- UPSTREAM-PR: NONE. The RAN absence proof is an observation about the shipped in-tree wiring
  (no bug; prior r34/r100/r110/r111/r116 class in-tree evidence). No change to
  theinterfold/interfold is justified by r150.

## NEXT (r151+) -- open, non-gated in the DIRECTION queue

1. SAFE-sponge M3 browser cell (r132 RAN anchors; 96.2% of the 71,981 g M3 cell; r148 wall DRAFT)
   -- the browser-side ask of the DIRECTION's "biggest combined impact across DKG AND browser."
   In-circuit side RAN-unpriced at current shape; DRAFT on box-2 64 GiB per r148 close.

2. ModU64::reduce_mod cost row (no prior round has spun it). RAN-unpriced; DRAFT on box-2 if
   the owner directs; no on-box incumbent.

3. (Explicit non-routine from r150): the C3 + C2b + C2a + C1 leaves with RAN-shipped range families
   are already priced; the (0) (0)-winner (C3 per-limb spec-A, r147) is informative and owner-gated
   at item (5). r150 does not unroll that gate; it leaves the owner-gate to the owner.

4. Owner-gated tolerant intake: (3) I18/I19, (4) LIVE-NETLINK, (5) C6 in-tree ship (r115-class),
   (6) box-2 provisioning. r150 touches none of these.