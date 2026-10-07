# r170 plan - C1 eek + sk solo legs

Idea (per r159 RESUME RULE secondary, now promoted to single p1: every other
unsliced C1 cell is RAN; the C1 flat remainder eek+sk = 76,483 g was
RAN-by-subtraction only (r157 flat 203,506 minus r159 e_sm_lifted 127,023)).
This round runs the two direct solo legs:

  A1 = unblunt re-anchor (expect 1,634,722 g, r157/r159 golden delta 0)
  E  = eek solo NOP   (L186 comment-blocked in core/threshold/pk_generation.nr)
  Sk = sk solo NOP    (L189 comment-blocked)

NOT owner-gated, NOT C6-class, NOT a lever: measurement-only (solo-NOP
diagnostic in a worktree; restore byte-exact; receipts-only commit 0 .rs/.nr).

Budget: 3 compiles ~ 70-230 s wall each at 4 cores (~8-9 min) << 60-min budget.
Box: 8c / 32 GiB / 0 swap (verified pre-round).
## Integrity (corrections-first)
First Sk leg compiled at the wrong DEF basis (restore() after Leg E left DEF at
insecure-512; Leg S skipped the flip). Result 47,027 g / 24,180 ACIR (wall 3.1 s)
is mangled and preserved as `*_WRONGBASE_insecure512_*`. The leg was re-run twice
independently at secure-8192 (S2 + S2c), both 1,597,853 g / 549,763 ACIR digit-exact.
Load-bearing sk_solo = A1 - S2c = 36,869 g. Committed leg script has the flip
added before Leg S so future re-runs are correct.
