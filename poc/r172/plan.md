# r172 — family-pool PAYOFF model (DRAFT; owner-armed lane (iii))

Owner decision 2026-10-18 ~13:35 EDT armed lane (iii) as **DRAFT-ONLY**:
produce the payoff model + exact run command + where the run goes, as a
zero-compile round; the re-anchor leg stays a SEPARATE owner call.
This round is exactly that: 0 compiles, 0 .nr/.rs touched, receipts-only.

## The object

The **family pool** = the range-check family mass inside the four measured
DKG leaves (secure-8192 preset, N=19/T=9):

| row | leaf                         | live leaf   | family    | per-limb  | flat    |
|-----|------------------------------|-------------|-----------|-----------|---------|
| C1  | threshold/pk_generation      | 1,634,722   | 1,014,519 |   811,013 | 203,506 |
| C2a | dkg/ct0 e_sm checks          | 1,464,743   |   552,965 |   552,965 |       0 |
| C2b | dkg/e_sm_share_computation   | 2,586,563   |   552,965 |   552,965 |       0 |
| C3  | dkg/share_encryption bounds  | 2,124,549   |   729,117 |   557,065 | 172,052 |
|POOL |                              |             | **2,849,566** | **2,474,008** | **375,558** |

DKG total (r160 golden, cited not re-burned): 9,197,169 g.
Family pool = **30.98 %** of the DKG circuit; per-limb pool = **26.90 %**;
flat pool = 4.08 %. All pool digits RAN-verified this round by
`family_pool_payoff.py` re-reading the 40 committed `*_gates.json`
(11 identity checks, all delta 0, incl. the r164 V4-parity cell 208,896).

## The lever (what the payoff is FOR)

r115-C6-class **per-limb aggregate-bound redesign**: replace the per-limb
range-check loops (L = 3 limbs, `pub global L: u32 = 3` — RAN at both
pre-fold and post-fold secure/threshold.nr L24608) with ONE aggregate
bound over the limbs. The lever class is **owner-gated (item (5), CLOSED
2026-10-06)** — this document prices it, it does not authorize it.

- **Addressable surface** = per-limb pool only: 2,474,008 g.
  The flat pool (375,558 g) has no per-limb loop (r158/r163 RAN flat=0 for
  the twins; C1/C3 flats are 2-bound/constant checks) — NOT addressable.
- **Payoff(leaf) = per_limb(leaf) − A**, where A = the irreducible
  aggregate-check cost of the replacement. A is UNMEASURED (no aggregate-
  bound primitive has been built or gated): every A below is DRAFT.

## Scenarios (payoff in gates, % of DKG total)

| scenario | A (aggregate cost)            | payoff        | % total | label |
|----------|-------------------------------|---------------|---------|-------|
| 1        | 0 (idealised ceiling)         | 2,474,008 g   | 26.90 % | DRAFT |
| 2        | 13.69 % of pool (r166-calib.) | 2,135,361 g   | 23.22 % | DRAFT |
| 3        | 100 % of pool (full re-check) | 0 g           | 0 %     | DRAFT |

**Scenario-2 calibration [the only RAN anchor]:** r166 measured the ONLY
3-limb decomposition on the box — C2b V1 path limb cells
[383,185 / 314,026 / 314,026] g, sum 1,011,237 g, vs the combined V1 cell
1,149,657 g ⇒ a **shared block of 138,420 g = 13.69 % of the 3-limb sum**
is NOT three independent copies. Scaling that measured non-additivity ratio
onto the whole per-limb pool gives A ≈ 338,647 g and payoff ≈ 2,135,361 g.
This is a RATIO extrapolation from one path (C2b V1) to four leaves —
DRAFT by construction, but the ratio itself is RAN.

**Headline for the owner:** if the aggregate-bound redesign ever opens,
the honest price tag is **~2.1–2.5 M gates (23–27 % of the DKG circuit)**
at the pre-fold secure-8192 shape, minus whatever the aggregate check
itself costs. Scenario 3 is the honest floor-risk: if soundness forces a
per-limb re-check anyway, the lever pays zero.

## ⚠ SHAPE STALENESS (load-bearing caveat)

Every digit above was measured at the **pre-fold secure-8192 shape**.
The #2195 fold (2026-10-18, i5 @ 2226ef62f @ OM 51f90114f) changed the
secure preset itself — RAN this round via blob compare 4e37b277 → HEAD:
`configs/secure/threshold.nr` QIS / PLAINTEXT_MODULUS (1,000,000 →
17,000,000) / Q_MOD_T (964,929 → 13,178,113) and the range-check bit
widths (PK_GENERATION_BIT_E_SM 58→59, E_SM_LIFTED 147→144,
E_SM_QUOTIENT 89→85, PK 58→59, CT0_R 20→24) ALL MOVED. L = 3 did NOT
move. So the pool digits are structurally valid but numerically STALE vs
the new base — the same staleness flagged for the r152x–r171 tables in
[LEAN-1215]. The payoff BAND (23–27 %) is ratio-driven and more robust
than the absolute gates; the absolute numbers need the re-anchor leg.

## Exact run command + where the run goes (NOT run this round)

Re-anchor leg (owner call — separate authorization per the 13:35 EDT
decision; ~11 legs × ~220 s ≈ 40 min wall, peaks ~21 GiB < box 31 GiB):

```bash
# vessel = the r157/r163 harness (byte-proven): detached worktree at tip,
# in-worktree DEF insecure->secure flip, taskset -c 0-3, /usr/bin/time -v,
# nargo compile --force + bb gates -t noir-recursive-no-zk, sha-pinned
# pre/post restore. Receipts land in poc/r173/ on i5/dkg-research.
git -C /home/dev/interfold-research/interfold worktree add --detach \
    /tmp/r173 2226ef62f449aff77368563bf99fb731185c615f
# then per leaf (C1 pk_generation, C2a, C2b, C3): legs A1/B/C re-run
# verbatim from poc/r157/r157_legs.sh + poc/r163/r163_c2b_legs.sh with
# BASE=2226ef62f and the NEW secure-preset pre-shas re-locked;
# plus the r166 J0/J1/J2/Jall legs to re-measure the 13.69 % ratio.
```

Run destination: this box (8c/31 GiB/0-swap) is sufficient — every
involved leg peaked ≤ ~21 GiB historically. The gateway-cgroup cap lesson
from [LEAN-1215] applies: run under `systemd-run --user --slice=user.slice
--property=MemoryMax=infinity` if launched as a gateway child.

## Verdict

DRAFT (document + model + run command delivered; zero-compile as armed).
Payoff band 2,135,361–2,474,008 g (23.22–26.90 % of DKG) at the OLD shape;
absolute numbers gated on the re-anchor leg at the new secure-50-coeffs
base; the lever itself stays owner-gated (item (5) CLOSED).

UPSTREAM-PR: NONE (0 circuits/ + 0 crates/ delta; poc receipts only).