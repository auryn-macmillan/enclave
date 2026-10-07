# R167 - O4: source-side classification of the C2b-V1 non-additive shared block

## Idea (p1)
r166 measured the C2b V1 solo cell (1,149,657 g; ACIR 428,717) plus per-limb
solos J0/J1/J2 and the all-3 solo Jall. The per-limb cells sum to 1,011,237 g
(87.96% of V1); the residual 138,420 g (12.04% of V1, 5.35% of the C2b leaf)
is the NON-ADDITIVE shared block r166 left marked DRAFT until a commitments.nr
investigate. This round does that investigate: source read only, zero compile.

r166's listed next p1 (C2a per-limb twin split, 3 fns on the C2a SecretKey-
ShareComputation twin) is REFUTED at the source: C2a's V1
(share_computation.nr L124-135) carries ONE Polynomial (self.sk_secret) and
calls compute_share_computation_sk_commitment_checked (commitments.nr
L237-242), which is a single_polynomial_payload_checked over that ONE poly.
There is no per-limb array on the C2a side to split. C2a p1 becomes NO-OBJECT;
carry O4 forward (the only OPEN non-owner-gated p1 in the block).

## Upstream sync (RAN)
- git fetch origin: FETCH_RC 0; origin/main f2df52907 UNMOVED (rev-list
  f2df52907..origin/main = 0); left-right origin/main...HEAD = 0/110 pre-round.
- EB c98b0d1caa31 is-ancestor origin/main rc 0, LOCKED.
- git rebase-merge / rebase-apply ENOENT (no in-flight rebase).
- SC share_computation.nr sha256 prefix 44eb78d7 (341 lines) byte-flat.
- DEF circuits/lib/src/configs/default/mod.nr sha256 prefix 7f07de82.
- Porcelain PRE: 5 untracked files in poc/r166/ (B0/J0/J1/J2/Jall *_gates.json,
  the r166 worktree spills r166 never committed; receipts-only, re-folded into
  this round's commit). Porcelain POST: 0.
- No cargo / nargo gate (0 .rs and 0 .nr edits this round).

## Method
Source read only; all line anchors re-verified against the on-disk file this
turn (no memory carries; every quote is a read_file from this tick):
1. C2b V1 (share_computation.nr L200-221) operates on the C2b
   SmudgingNoiseShareComputation impl (the e_sm twin). Per-limb loop:
       for j in 0..L { let q = self.configs.qis[j]; let half = (q-1)/2;
          for i in 0..N { c = e_sm_secret[j].coefficients[N-1-i];
             centered = (c u64 > half u64) ? c - q : c; coeffs[i] = centered; }
          normalized[j] = Polynomial::new(coeffs); }
       and one commit: assert(compute_share_computation_e_sm_commitment_checked::<N,L,BIT_SECRET>(normalized) == expected_secret_commitment).
2. C2a V1 (L124-135) operates on the SecretKeyShareComputation impl (the sk
   twin). ONE poly, self.sk_secret; one negate: v = sk_secret.coefficients[N-1-i]
   for i in 0..N (NO centering - C1's sk is trinary, C2a opens the trinary, no
   half-shift needed). Then
   compute_share_computation_sk_commitment_checked::<N, BIT_SECRET>(reversed_sk).
3. commitments.nr L237-242 compute_share_computation_sk_commitment_checked:
   payload = single_polynomial_payload_checked::<N, BIT_SK>([].as_vector(), sk);
   compute_commitment(payload, DS_SHARE_COMPUTATION).
4. commitments.nr L305-310 compute_share_computation_e_sm_commitment_checked:
   payload = multiple_polynomial_payload_checked::<N, L, BIT_E_SM>([].as_vector(), e_sm);
   compute_commitment(payload, DS_SHARE_COMPUTATION).
5. helpers.nr L104-115 flatten_checked: for j in 0..L { packed = pack_checked::<A,BIT>(poly[j].coefficients); for i in packed.len { inputs.push(packed[i]) } }.
   helpers.nr L71-100 pack_checked(BIT): nibble_bits and group = packing_layout
   (uniform here); for each chunk: for i in 0..take { digit = v + base;
   digit.assert_max_bit_size::<((BIT+3)/4)*4 + 4>(); acc = acc*radix + digit };
   pad (group - take) with digit = base.
   The assert fires ONCE PER COEFFICIENT (per digit slot).
6. polynomial.nr L173-182 range_check_2bounds (C2b FAMILY poly check; NOT
   the V1 commitment) - cited here to confirm the V1 path does not use it:
   the V1 commitment goes through pack_checked + compute_safe, not range
   checks.

## Digit-recompute (RAN - python vs on-disk poc/r166 JSON + committed captions)
From on-disk poc/r166/{B0,J0,J1,J2,Jall}_gates.json (circuit_size / acir_
opcodes):
- B0    2,586,563 g /  854,722 ACIR (C2b unblunt, secure-8192)
- J0    2,203,378 g /  711,818 ACIR
- J1    2,272,537 g /  715,458 ACIR
- J2    2,272,537 g /  715,458 ACIR  [J1 == J2 digit-identical]
- Jall  1,436,906 g /  426,005 ACIR  [== r164 V1 solo 1,436,905 + 1 g warm-cache]
Cells (leaf - solo leg; r166 ruled identity, this round re-derived):
- V1 cell       = 2,586,563 - 1,436,906 = 1,149,657 g / 428,717 ACIR
- limb 0 cell   =   383,185 g / 142,904 ACIR
- limb 1 cell   =   314,026 g / 139,264 ACIR
- limb 2 cell   =   314,026 g / 139,264 ACIR
- sum of 3 limb cells = 1,011,237 g / 421,432 ACIR
NON-ADDITIVE SHARED BLOCK (RAN):
  gates = 1,149,657 - 1,011,237 = 138,420 g (== r166 quote, DELTA 0)
  ACIR  = 428,717 - 421,432 = 7,285 g
  per-N: 138,420 / 8,192 = 16.8970 gates/coef ; 7,285 / 8,192 = 0.8893 ACIR/coef
GATES-PER-ACIR SIGNATURE (RAN):
  non-additive shared = 138,420 / 7,285 = 19.001 gates / ACIR
  limb cells average  = 1,011,237 / 421,432 = 2.400 gates / ACIR
  ratio = 7.918x denser in shared state than in any per-limb cell.

CROSS-TWIN (r165 already RAN; this round cites R165 on-disk captions only, no re-burn):
  C2a V1A cell (r165) = A - V1A = 1,464,743 - 1,436,905 = 27,838 g / 16,740 ACIR.
  Twin differential = (C2b V1) - (C2a V1) = 1,149,657 - 27,838 = 1,121,819 g
                   = (r164 twin gap 1,121,820 - warm-cache 1 g), DIGIT-CARRIABLE.
  dV2 = (C2b V2) - (C2a V2) = 0 (both N x L = 8192 x 3 equality checks,
  gate- and opcode-identical across twins; r165 RAN digit-exact).
C2b leaf ACIR - C2a leaf ACIR = 854,722 - 442,744 = 411,978 ACIR (RAN r165/r166).

## FINDINGS
F1 (RAN, digit-carry only): r166's non-additive 138,420 g re-anchored on-disk
to 0 delta on secure-8192 base; the 12.04% of V1, 5.35% of leaf ratios hold
exactly (RAN python-actor identity; every digit from on-disk).

F2 (RAN, ratio signature): The 12.04% non-additive block is 7.918x denser
in the gates/ACIR ratio (19.001 g/ACIR) than the per-limb cells (2.400 g/ACIR).
Per-limb cells are per-coefficient territory: pack_checked accumulates each
digit into `acc = acc*radix + (v+base)` per chunk (helpers.nr L80-99), and
the per-limb 2.4 gates/ACIR comes from the one
`assert_max_bit_size::<((NIBBLE+3)/4)*4 + 4>()` (L89) per coefficient.
The non-additive block is 19.0 per ACIR, ~8x denser, because it sits
OUTSIDE the per-coefficient pack loop: after flatten_checked (L104-115)
produces one shared [Field] vector, compute_commitment (commitments.nr
L122-124) feeds that vector into compute_safe (helpers.nr L245-252), a
single sponge start -> absorb -> squeeze -> finish shared by all three
polys. Removing two of the three polys does not fold that one shared
absorb/squeeze away, because the j-index dependency means the solver
cannot merge it into any per-poly chain; the residue stays. The 138,420 g
lives in that shared absorb/squeeze residue, not among the three packs.
The RAN part is the ratio number (19.001 vs 2.400). The mechanism
attributing it to the sponge is MINE (DRAFT), from the source read; not
labeled RAN further.

F3 (SOURCE, read on-disk this tick): The C2b V1 limb loop
(share_computation.nr L200-221) is byte-identical across the three `j`
iterations except that `qis[j]` and `e_sm_secret[j]` change index - same
reversal + center (the `c as u64 > half as u64` test at L211), same
per-coefficient path, same final
compute_share_computation_e_sm_commitment_checked assert (L217-218). RAN
r166 already showed J1 cell == J2 cell digit-identical in BOTH gates
(314,026) and ACIR (139,264). So the +69,159 g limb-0 premium over limbs
1/2 is NOT a source-structural loop variant - the loop bytes are the same
for all three `j`. The only per-limb source variation is the `qis[j]`
modulus constant (line 203) used in the center half-shift. DRAFT (not
probed this round): limb-0's premium is thus attributed to `qis[0]`
taking a different path through the `half` comparison than qis[1]/qis[2];
r166's per-limb cells carry the number, the mechanism is not RAN-anchored.

F4 (SOURCE, REFUTE): r166's listed p1 (C2a per-limb twin, 3-normalize
blocks on the sk side) is NO-OBJECT AT SOURCE: C2a V1 (share_computation.nr
L124-135) is a 1-poly single_polynomial_payload_checked
(commitments.nr L237-242). The only loop in C2a V1 is the for-i in 0..N
reversal; there is NO `for j in 0..L` loop to solo. C2a per-limb p1 dropped.

F5 (structure-decomposition, NOT an additive partition, RAN by identity):
C2b V1 cell (1,149,657 g) is the span measured by B0 - Jall. The three
per-limb solo cells (J0, J1, J2) overlap on the same span and therefore SUM
to 1,011,237 g = 87.96% of the cell (this is r166's decomposition). The
shared-block residual = 1,149,657 - 1,011,237 = 138,420 g = 12.04% of
the cell, and 87.96 + 12.04 = 100.00% EXACTLY. F5's statement is that the
V1 cell = (per-limb solo cells, joint span) + (shared-block residual,
NOT additive over the per-limb cells). The per-limb cells are NOT disjoint;
they overlap on the same joint V1 span. RAN identity, zero free parameters.

## NO NEW LEVER
The C6-class per-limb aggregate redesign stays CLOSED per the 2026-10-06
~02:25Z owner closure line ((3) C4-consumer acc-pin / (4) LIVE-NETLINK
multi-node / (6) box-2 full-shape secure-8192, all CLOSED). The 138,420 g
non-additive block IS A SOURCE-COST SIGNALLING a SOLVER-timeline shape,
SUSPECTED, and MUST NOT be treated as a pre-approved lever. The same as
r166: any per-limb or shared-block redesign lands in commitments.nr or
helpers.nr (flatten_checked / pack_checked) and remains subject to the
standing C6-class plus owner gate.

## Upstream / PR
Origin UNMOVED, no rebase, no new commit afterwards. No upstream PR candidate
(0 circuits/ + 0 crates/ source delta; receipts only).

## Budget
Wall: not compiled this round. Wall of this ticket: ~30 min (source read +
r166 JSON re-parse). Box: not compiled, no OOM surface.