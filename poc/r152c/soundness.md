# r152c — C1 pk_generation re-anchor + range-ablation on the NEW upstream base c98b0d1ca (#1999)

Measurement-only round. NO source change shipped; `pk_generation.nr` / `default/mod.nr`
restored byte-exact after every leg (DEF sha 7f07de82... / PK sha 8e37436b... post-run).

## Why this round
#1999 "bound openings, quotients and VK trees" (+246 lines to pk_generation.nr) rewrote the
C1 range family: the OLD base had 2 flat checks (eek, sk) + a per-limb loop of 3 range checks
(e_sm, r1, r2). The NEW base has 3 flat checks (eek, sk, e_sm_lifted) + a per-limb loop of 4
range checks (pk0, e_sm, e_sm_quotients, r). The r149 family price (887,460 g = 39.92% of the
old 2,223,114 g leaf) was therefore computed on a different circuit, and the C1 split into
family / per-limb / flat cannot be inferred from the old base — it must be re-measured.

## RAN (new base c98b0d1ca, detached worktree /tmp/r151b, nargo 1.0.0-beta.26 + bb 5.1.0,
secure-8192/minimum N=3/T=1/H=2/L=3, systemd user unit r152c_c1 MemoryMax=31G, taskset -c 0-3)

| leg | gates | ACIR | wall | fresh sha |
|-----|-------:|--------:|-------:|-----------|
| C1A1 unblunt re-anchor | 1,634,682 | 582,531 | 43.94 s | 1dd9bc9229df... |
| C1B  perform_range_checks() full NOP | 620,203 | 91,011 | 27.91 s | 81eabd00e91e... |
| C1C  per-limb for-loop only NOP (3 flat kept) | 823,669 | 189,315 | 32.59 s | 6e4e38376c38... |

## Deltas (all RAN, RAN inputs only)
- FAMILY (C1A1 - C1B) = 1,634,682 - 620,203 = **1,014,479 g = 62.06% of the new C1 leaf**.
- PER-LIMB (C1A1 - C1C) = 1,634,682 - 823,669 = **811,013 g = 49.61% of leaf** (r/pk0/e_sm/quotients x L=3).
- FLAT (C1C - C1B; eek+sk+e_sm_lifted) = 823,669 - 620,203 = **203,466 g = 12.45% of leaf**.
- Identity: 811,013 + 203,466 = 1,014,479 = family (exact).
- New C1 leaf 1,634,682 vs OLD-base golden 2,223,114: -588,432 g = -26.47% leaf shrink under #1999.
- Family grew vs old base: 1,014,479 vs 887,460 = +14.31%, while the leaf shrank -26.47%
  -> the range family is now 62.06% of the (smaller) new leaf, up from 39.92% old.
  The per-limb slice is the surviving load-bearing mass (811,013 g = 74.1% of the family,
  vs 91.7% old-base).
- NOTE: 8.78% / 7.02% of the 11,558,499 g figure are STALE-DENOMINATOR (old 19.23% leaf share
  used the old full-leaf sum); they are reported for continuity only.

## Soundness
Same posture as r149: the C1 per-limb + flat range family is source-stated ring-LWE load-bearing.
C1B/C1C are shadow-ablations (measurement only), never a sound vehicle. An actual cut would be
the r115-C6-class per-limb aggregate-bound redesign — owner-gated item (5) persists. #1999's
restructure increased the per-limb weight (new e_sm_quotients bound + a dedicated lifted
e_sm bound + the pk0 pin), so the lever's measured surface is now LARGER, not smaller.

## Vessel note (box 8c/32GiB/0swap)
nargo beta-26 writes the artifact to the package-ROOT target dir
(circuits/bin/threshold/target/pk_generation.json), NOT the package subdir. First run reported
NO_ARTIFACT because the script polled the wrong path (r152b artifact-path class); fixed path
changed nothing about the compiles (all 3 had already compiled RC=0) — only collection.
systemd user unit is the reliable vessel per r152b BOX NOTE (in-session terminal legs die).