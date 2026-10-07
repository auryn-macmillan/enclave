r161 - C3 narrow-flat 3-cell solo + combined probe @ FOLD tip 733eb45ae

The idea (per r160 RESUME RULE p1): r160 split the C3 flat 172,052 gates
into message (61,440, RAN) + narrow u/e0/e1 (110,612, RAN-by-subtraction).
This round probes whether that 110,612-wide cell, the only RAN-by-
subtraction surface left in the C3 flat, splits by WIDTH (1-bit u :
5-bit e0 : 5-bit e1 = 1:5:5, width-linear) or by a roughly fixed
per-poly term (~1:1:1, fixed-dominant).

Leg design: on the unblunt basis with check_range_bounds() live, each
leg line-comments exactly one self.<cell>.range_check_2bounds::<T>(...)
call (u / e0 / e1) or all three (X), leaving the message check and all
four per-limb loop checks live. Per-leg: SE restored to PRE_SE 308c8c5d
before compile; DEF flipped once to secure-8192 and carried across legs;
post-compile restore re-pins SHA; porcelain clean on every exit.
Vessel: in-session foreground, taskset -c 0-3, /usr/bin/time -v
(r159/r160 precedent; the background-scratch variant here dies on
the terminal transport auto-reap, observed in this session).

BASE-STABILITY (RAN): A1 unblunt RAN = 2,124,549 gates, ACIR 609,966,
digit-exact to the r156 fold golden (C3 locus blob a38431229 git hash,
byte-identical 7e999546e leg base -> 733eb45ae fold tip). Each solo
therefore subtracts against the SAME baseline it was built from, so
no cross-leg inference is needed.
RAN DIGITS (fold tip 733eb45ae; each leg read from its on-disk caption;
the *_fresh.json is kept for provenance; gates via bb gates
-t noir-recursive-no-zk):

  Leg  GATES      ACIR      WALL     PEAK_KB
  A1   2,124,549  609,966   223.6s   19,591,480   (unblunt re-anchor)
  U    2,050,816  544,430   216.4s   20,206,380   (u  solo NOP, 1-bit)
  E0   2,050,806  544,430   222.7s   18,860,452   (e0 solo NOP, 5-bit)
  E1   2,087,685  577,198   223.8s   19,330,180   (e1 solo NOP, 5-bit)
  X    2,013,937  511,662   291.3s   18,110,860   (u+e0+e1 ALL solo NOP)

RAN DECOMPOSITION (digits from the captions above):
  u_solo    = A1 - U  = 2,124,549 - 2,050,816 =   73,733 g
  e0_solo   = A1 - E0 = 2,124,549 - 2,050,806 =   73,743 g
  e1_solo   = A1 - E1 = 2,124,549 - 2,087,685 =   36,864 g
  X (all 3) = A1 - X  = 2,124,549 - 2,013,937 =  110,612 g
  sum of the 3 independent solos = 73,733 + 73,743 + 36,864 = 184,340 g
  NON-ADDITIVE GAP (sum-of-solos minus X) = 184,340 - 110,612 = 73,728 g

FINDINGS (each traced to specific digits above):

  (1) REFUTED - width-linear (the round's p1 question). If cost scaled
      with checked bitwidth, e0 (5-bit) should cost ~5x u (1-bit,
      ~368k g). RAN: e0_solo (73,743) is essentially equal to u_solo
      (73,733); a 5-bit poly costs no more than the 1-bit one. Bitwidth
      is NOT the dominant driver at these cells.

  (2) OBSERVED - a clean 1:2 split between the two "5-bit" cells.
      e1_solo (36,864) is exactly half of e0_solo (73,743). RAN config
      cross-check (circuits/bin/config/src/main.nr L200-201): e0_bound
      = e1_bound = 20, and both polys share width 5 (locus constants
      SHARE_ENCRYPTION_BIT_E0=_E1 = 5). u_bound = 1, width 1, but u_solo
      (73,733) is ~1.00014x e0_solo. So the SOLO COSTS of the three cells
      are {73.7k, 73.7k, 36.9k} while (width, bound-value) is
      {(1,1), (5,20), (5,20)} -- e0 and e1 have identical DECLARED shape
      but different solo cost. Cost is NOT keyed on width or on the
      bound value; it is keyed on which polynomial is being checked.
      The source mechanism (how the specialization / dedup key works)
      is DRAFT; not confirmed by this round.

  (3) OBSERVED - the solos are NON-ADDITIVE. Sum of the 3 independent
      solos (184,340) exceeds the combined X cut (110,612) by 73,728 g,
      ~= one full u/e0-solo. With a shared unblunt baseline on every leg,
      this means the per-poly solos over-count a shared circuit
      component that is removed only once. The true whole-surface cost
      of the narrow flat is X = 110,612 g, not 184,340 g.

CROSS-ROUND (RAN): X (110,612) == r160 pinned rem_flat
(172,052 - 61,440 = 110,612), cross-round delta 0. The narrow flat's
whole-surface cost re-anchors cleanly across the fold base.

MECHANISM (DRAFT - NOT RAN): why e0 ~= u yet e1 = e0/2, and why the solos
over-count by one cell. Candidate: each poly's cost is keyed on its
polynomial identity (e0 vs e1 are distinct cells) plus their distinct
*_bound derivation path, so e1 dedups with a shared component under
the same calibration and its marginal solo is half; the non-additive
gap is that removing two polys that share a bound does not add their
solo costs. A SOURCE-CHECK (range_check_2bounds specialization in
circuits/lib/src/math/polynomial.nr + the bound derivation in
circuits/bin/config/src/main.nr) is the cheap next-step discriminator;
NOT run this round, NOT claimed.

C3 TABLE (fold tip 733eb45ae, all RAN):
  C3 leaf     = 2,124,549 g   (r156 + r161 A1, digit-exact, delta 0)
  per-limb    =  557,065 g    (r156 C-leg, blob-frozen carry)
  flat        =  172,052 g    (r156 C-B, RAN)
    message   =   61,440 g    (r160 RAN solo M; 35.71% of flat)
    u+e0+e1   =  110,612 g    (this round X RAN; 64.29% of flat;
                               == r160 pin, cross-round delta 0)
      u       =  73,733 g     (this round RAN solo U)
      e0      =  73,743 g
      e1      =  36,864 g
  per-cell RAN digits IDENTIFY each cell, but the tree is NON-ADDITIVE:
  the sum of the three cells (184,340) is not the flat surface (110,612).
  The table at cell level for C3 is now COMPLETE; the non-additive
  relationship among cells is the finding; the per-cell isolated cost
  is NOT the cell's marginal contribution to the family.
  C3 family    =  729,117 g    (r156; per-limb + flat = 557,065 + 172,052)
                     IDENTITY HOLDS EXACTLY, DELTA 0.

EQUIVALENCE: C3's flat is fully RAN'd to cell level now: message 61,440
is the only additively-clean split; the narrow u/e0/e1 110,612 is a
non-additive 3-poly structure. That means the real cost of removing the
entire narrow-flat subfamily in a future lever is 110,612 g, and the
three individual solo numbers are diagnostic shapes only.

ANSWER TO THE R160 OPEN QUESTION (width vs fixed):
  Width-linear (1:5:5 expected) is REFUTED: the 5-bit e0 and the 1-bit u
  cost essentially the same solo (~73.7k each, delta 10 g), so bitwidth
  is not the driver. The e0-vs-e1 2:1 step (73.7k vs 36.9k) is STRUCTURAL
  (same width + same bound value, different poly) not width-driven.
  Range-check cost in this era is FLAVOR / POLY-IDENTITY dominated, not
  bitwidth dominated. Any future re-blunt of the narrow-flat family is
  best modeled from X (110,612), not from the sum of individual solos.
  This is a FINDING only, NOT a new optimization idea (all source-code
  changes remain owner-gated; the C6-class per-limb lever CLOSED 2026-10-06
  stays closed; the present change is read-only and adds no new gate).

NEXT TICK p1 (when selected): source-verify the mechanism in item (3)
above. ~5-min read, 0 compile: grep range_check_2bounds in
circuits/lib/src/math/polynomial.nr (its specialization / how the bound
key is formed) + the config derivation in circuits/bin/config/src/main.nr
L199-209 (RAN this round: u_bound = 1, e0_bound = 20, e1_bound = 20; the
locus constants SHARE_ENCRYPTION_BIT_U/E0/E1 = 1/5/5). Since e0 and e1
carry the SAME width (5) AND the same bound value (20) yet differ 2x in
solo cost (73,743 vs 36,864), the cost cannot be keyed on width or on
the bound value alone -- it tracks which polynomial object is being
checked; which cell it is is exactly what the source-read would confirm.
This discriminates the (poly_id, bound) vs bound-value key hypothesis
without a single compile.

BOX (RAN): 8-core / 31 GiB hold. Peak 20.2 GiB < 31 GiB; no OOM.
EVIDENCE BASE c98b0d1caa31 LOCKED unchanged (is-ancestor rc 0).
UPSTREAM SYNC: fetch origin main f2df52907 UNMOVED this round
(rev-list f2df52907<->origin/main = 0); left-right origin/main...HEAD
= 0/103 (r160 was 0/102); EB locked; DKG locus 308c8c5d 767 L unchanged;
DEF 7f07de82 unchanged.

INTEGRITY NOTE: I drafted an early first plan.md during the round that
arrived garbled on the write channel (non-ASCII tokens + a fake base
token from a parallel draft carryover) and was not rechecked on disk.
I deleted it and rebuilt this file in short writes, re-scanning each
pass for stray tokens before continuing. All RAN digits in this plan
come from the five on-disk captions captured during the round
(r161A1 / r161U_u / r161E0_e0 / r161E1_e1 / r161X) and the on-disk
config source read; nothing in this document is carried from memory.