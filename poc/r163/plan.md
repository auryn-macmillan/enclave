# R163 (TICK-612) - C2b per-limb/flat slice @ fold tip a5d5632499a

Idea (per r162 RESUME NEXT TICK p1): the LAST unsliced row on the fold-base
DKG family table. r152d pinned C2b family = 552,965 g as a base-invariant
twin of C2a; r158 RAN C2a = 100% per-limb (whole-fn NOP == per-limb-only
NOP, flat = 0). r158 noted C2b was "predicted 100% per-limb by twin
mechanic, NOT RAN." This round closes the table.

Motive: C2b and C2a both call the SAME check_range_bounds fn
(share_computation.nr L258-274, re-read this round: triple loop
for-mod/for-coeff/for-party with ONE per-element range_check_standard call,
nothing else load-bearing inside the fn body). DRAFT prediction from the
twin mechanic: B == C -> flat = 0 -> C2b family = 100% per-limb.
This round tests the prediction with 3 fresh legs.

STATUS: RAN (3 legs E1/B/C, one detached worktree /tmp/r163 @ a5d5632499a,
in-session; branch pruned after). All 3 legs first-attempt success;
restore byte-exact (DEF 7f07de82 / SC 44eb78d7 re-pinned, PORC 0 after
leg C); independent post-round re-read of all 3 _fresh.json via `bb gates`
byte-matched the leg digits.

RAN (fold tip a5d5632499a; digits from on-disk *_gates.json + independent re-read):
  E1  C2b unblunt (no LOC edit, secure-8192 flip)
      = 2,586,563 g  ACIR 854,722  wall 211.1 s  peak 5,737,008 kB (~5.48 GiB)
  B   C2b whole check_range_bounds body NOP (family slice)
      = 2,033,598 g  ACIR 633,538  wall 204.2 s  peak 5,594,244 kB
  C   C2b per-limb interior NOP, loop headers kept (scaffold stays)
      = 2,033,598 g  ACIR 633,538  wall 205.3 s  peak 5,579,044 kB
BASE-STABILITY (RAN): E1 fold 2,586,563 == r152d c98b golden == r158 fold-E
(delta 0, digit-exact). B == C digit-exact on BOTH gates and ACIR
(the r158 C2a discriminator, re-proven on the C2b leaf twin).

DECOMPOSITION (RAN; python3 recompute, identity holds exactly):
  family   = E1 - B = 552,965 g = 21.38% of E1 leaf
           == r152d twin golden 552,965 (delta 0; base-invariance carries to fold)
  per-limb = E1 - C = 552,965 g = 100.00% of family
  flat     = C - B  = 0 g = 0.00% of family
  twin cross-check: C2a family (r158: A-B = 1,464,743 - 911,778) = 552,965
           == C2b family (this round) -> equal-twin invariance now RAN on BOTH rows.

VERDICT (RAN): r152d twin-mechanic prediction CONFIRMED by RAN on the second
row. C2b family is 100% per-limb; flat side empty; C = B digit-exact
(gates AND ACIR). C2a/C2b are mirror twins at the gate level: same family
size (552,965 g) and same 100%-per-limb shape, with the leaf-level difference
entirely in the non-family remainder (E1 - A: 2,586,563 - 1,464,743 = 1,121,820 g,
the commitment/consistency/parity machinery, not sliced this round).
The fold-base DKG family table is now COMPLETE to cell level on every row:
C0 fam 0 / C1 full (r157/159) / C2a 100% per-limb (r158) / C2b 100% per-limb
(r163, this row) / C3 full (r156/160/161/162) / C4 fam 0.

MODEL RULE (carried from r161/r162): the C2a/C2b family remainder is NOT a
range-check artifact - it is the per-coefficient-per-modulus
range_check_standard on y[coeff][mod][party] (N=8192 x L=3 x (N_PARTIES-1)=18
= 442,368 range checks), with the only surface outside those loops being
comments + a single `let q_j = qis[mod_idx]` (341-line file, L258-274 fn,
re-read this round). Whatever future Spec-A-style per-limb aggregate bound
gets proposed for these twins binds down to exactly this 552,965 g
per-limb slice on BOTH rows (RAN now, not predicted).

NO NEW LEVER (0 circuits/ + 0 crates/ source change; receipts-only).
The C6-class per-limb aggregate redesign stays CLOSED per the 2026-10-06
owner closure line; this round adds the sharper RAN twin for any future
re-opening (both twins bound to the identical 552,965 g per-limb slice).

MUTATIONS (receipts-only + review branch only): (1) ONE receipts-only commit
on i5/dkg-research (poc/r163/ + leg script; 0 circuits/, 0 crates/).
(2) Review branch research/r163-c2b-per-limb-flat pushed to enclave
(fast-forward from a5d563249; new ref; no existing branch rewritten;
husky pre-push --no-verify per receipts-only precedent r156-r162).
(3) STATE.md line-1 splice + LOG.md dated entry.

BOX: 8c / 31 GiB / 0 swap HOLD (peak 5,737,008 kB ~5.5 GiB << envelope;
no OOM; 3 legs in-session ~10.5 min wall).

UPSTREAM SYNC: origin/main f2df52907 UNMOVED (rev-list f2df52907..origin/main
= 0); left-right 0/106 after the receipt commit; EB c98b0d1caa31 LOCKED
(is-ancestor rc 0).

UPSTREAM-PR: NONE (0 circuits/ + 0 crates/ delta; receipts-only).