# r152f — C0 (dkg/pk) re-anchor at NEW upstream base c98b0d1ca (#1999); closes the per-leaf table

One idea: re-anchor C0 (the `dkg/pk` bin, C0 in the r39/r75 numbering = DKG
public-key commitment leaf) at the new base `c98b0d1ca`; this is the last of the
`r152b → r152f` leaf re-anchors opened by #1999 (`bound openings, quotients and
VK trees`, +2163/-745 across `circuits/lib/` but **0 lines** in `circuits/bin/dkg/pk/`
and **0 lines** in `circuits/lib/src/core/dkg/pk.nr`).

## Premise verify (fastest path, source-first)

1. `git diff d62e22e16..c98b0d1ca --stat -- circuits/bin/dkg/pk/ circuits/lib/src/core/dkg/pk.nr`
   → **empty**. pk C0's bin + source are untouched by #1999.
2. `circuits/lib/src/core/dkg/pk.nr` calls
   `crate::math::commitments::compute_dkg_pk_commitment::<N,L,BIT_PK>`
   (`commitments.nr:190`). `commitments.nr` itself DID change in #1999
   (`circuits/lib/src/math/commitments.nr` +123 lines) — the question the re-anchor
   answers is: does C0's NEW gg-encoded artifact remain byte-identical to the old?
3. Range-check check: the C0 body has **0** `range_check` /
   `check_range_bounds` invocations in its direct cone (40-line file:
   `Pk::new` + `Pk::execute` → `compute_dkg_pk_commitment`). Confirms the
   r99/r100/r145/r150 class (C0 = pure-leaf, no range family).

## Method (r145/r146/r152c/r152d form, measurement-only, NEVER shipped)

Detached worktree `/tmp/r151b @ c98b0d1ca` (porcelain 0 pre+post), systemd user
unit `r152f_c0.service` (`MemoryMax=31G, taskset -c 0-3, Restart=no`). For the
single A0 leg: preset flip (insecure-512 → secure-8192, N=3/T=1/H=2/L=3),
`taskset -c 0-3 /usr/bin/time -p nargo compile --force` on
`circuits/bin/dkg/pk`, gate with `bb gates -t noir-recursive-no-zk`, then
**byte-exact restore** (both config and in-tree JSON pinned, `PRESERVED_CONFIG=BYTE_EXACT`).

## RAN result (this round — 3 independent fresh compiles, all digit-identical)

- Fresh `A0_fresh.json`: `572e71bf6de9e40c09b6d148a321b55937d706b81af9d696b432cc655d53e299`
  — **BYTE-IDENTICAL to the pre-round `pk.json`** (r44-era committed artifact;
  the same bytes that anchored the r39/r75/r100 287,727-g golden).
- Gates via `bb gates`: **287,727 g / ACIR 14,568** — digit-exact to r39/r75/r100 golden.
- Wall 6.60 s (POSIX `time -p` output `real 6.60`; the `WALL=0.00s` in the original
  `A0.r152f` caption is the same r152b/r152c BOX-NOTE class: POSIX `time -p`
  does not emit a `Maximum resident set size` line and the summary parser's
  `Elapsed (wall clock)` label never matches, so both fields are blank — the
  actual wall and peak are the `real 6.60` from `A0_timev.log` and the single
  ram_trace sample `1358 kB` captured 8s after start, inside the wall, so the
  peak is <1.4 GB class, matching r73's `PEAKRSS 721,484 kB (699 MB)`).
- Restore: `PRESERVED_CONSERVE=ALL_OK`, `PRESERVED_CONFIG=BYTE_EXACT`,
  `PORC_AFTER=0`. Worktree `/tmp/r151b` left PORC 0 after this round.

## Load-bearing finding

C0 is **base-invariant** across #1999: the re-compiled artifact is
byte-identical to the pre-round committed artifact (which already locked in the
r39/r75/r100 287,727 g / 14,568 ACIR golden), and the gate count is digit-exact.
Consequence for the C6 in-tree ship re-measure (next round): C0's family
contribution is 0 g (no range family, proven at source) both before and after
#1999 — no new drop for the C6 cap story. The base-invariant case at C0 is
additive to the base-invariant case at C2a/C2b C2a+C2b family (552,965 g, r152d):
three of the six leaves are "base-invariant family" (C0, C2a, C2b), two are
"family shifted" (C3, C1), one is "family absent by structure" (C4).

## Final new-base per-leaf table (re-anchored, RAN in this round + r152b through r152e)

| Leaf | OLD  (d62e22e base) | NEW (c98b0d1ca base) | Drift | New fam | New fam% | Source |
|------|---------------------|----------------------|-------|---------|----------|--------|
| C0   |     287,727 (2.49%) |  287,727 (3.13%) |   +0 (+0.00%) |     0 g |   0% | r152f (this round) |
| C1   |  2,223,114 (19.23%) | 1,634,682 (17.77%) | −588,432 (−26.47%) | 1,014,479 g | 62.06% | r152c |
| C2a  |  1,446,311 (12.51%) | 1,464,743 (15.92%) | +18,432 (+1.27%) |  552,965 g | 37.75% | r152d |
| C2b  |  2,888,964 (24.99%) | 2,586,563 (28.12%) | −302,401 (−10.47%) |  552,965 g | 21.38% | r152d |
| C3   |  2,966,353 (25.66%) | 2,125,396 (23.11%) | −840,957 (−28.35%) |  729,110 g | 34.30% | r152b |
| C4   |  1,746,030 (15.11%) | 1,098,865 (11.95%) | −647,165 (−37.06%) |        0 g |   0% | r152d (family absence re-confirmed) |
| **Total** | **11,558,499 (100%)** | **9,197,976 (100%)** | **−2,360,523 (−20.42%)** | **2,849,519 g** | **30.98%** | r152b/r152c/r152d/r152f (this round closes) |

Old-new family-pool delta: −282,527 g (old 3,132,046 = 27.10% of old base →
new 2,849,519 = 30.98% of new base). Between the two claims:
 - The absolute number of range-family gates fell slightly (−9.02%).
 - The *fraction* of the DKG that is range-family rose (+3.88 pts) because the
   leaf base fell more than the family base (−20.42% leaf vs −9.02% family).

Answer to the r145 r152d-era DRAFT-pending "new full-leaf denom": the new-base
per-leaf DKG total is **9,197,976 g** (−20.42% vs old 11,558,499 g) and the
new-base family pool is **2,849,519 g = 30.98% of the new base**.

## Note on `first_pass/`

`first_pass/` contains the first pass's artifact and stderr log — kept for
audit because it records the `set -u` + `_R152F_RESTORED` bug that caused
pass 2 to crash after the compile succeeded (pre-fix: the leg did not
restore the config, leaving the worktree dirty). The third (final) pass
restored correctly. The `first_pass/` data is also **digit-identical on gates**
to the final pass — independent confirmation of byte-determinism.

## NEXT round
Re-measure the r115 C6 in-tree -13.943% RAN cap **at the new base c98b0d1ca**
(the i5/dkg-research in-tree `i6_c6_cap.c6` shape), per the standing
owner-poked 2026-10-03 POKE → C6 registered per-diff is usable for this
single re-measure; a ship would still need its own fresh owner re-authorization.
The new-base floor for that re-measure is now done — this table is the
RAN-verified input to the re-measure, so the C6 ship re-apply is now a
single-round task (one more round after the re-measure).