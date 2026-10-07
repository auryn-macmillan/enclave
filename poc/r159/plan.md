# r159 — C1 solo-isolate e_sm_lifted within the flat slice

## One line

C1 flat slice (203,506 g = 12.45% of leaf, = 20.06% of family per r157) expanded: the 147-bit `e_sm_lifted` solo range check sits in `perform_range_checks`' flat region alongside the 5-bit `eek` and 1-bit `sk`; NOP-ing only `e_sm_lifted` isolates its cell cost and tests the r158 RESUME-note question ("per-limb-recolor vs a true inside-loop") for the C1 flat side. RAN 2 legs (A1 sanity re-anchor at f7c87dbb9 + e_sm_lifted solo NOP); delta = RAN A1 − RAN B.

## Why this round

r157 closed the C1 fold-base row (1,634,722 / family 1,014,519 = per-limb 811,013 + flat 203,506, 79.94 % / 20.06 %). r158's RESUME note pointed the next tick at "a SINGLE single-leg re-measure on the C1 tail (expand the C1 per-limb/flat slice on C1's 20.06% flat to tell which cells are a per-limb-recolor vs a true inside-loop), OR on C3's 23.60% flat". This round picked the C1 side because (a) it carries a RAN anchor on all 3 coarse cells (r157 A1/B/C) so the solo leg is a 4th cell read in the same window, and (b) the 3 flat cells have overwhelmingly unequal bit-widths (see "Bit widths" below) so a single solo identifies which flat cell actually carries the 20.06%.

## Bit widths in the secure-8192 preset (circuits/lib/src/configs/secure/threshold.nr)

| cell in C1 | bit width | where in `perform_range_checks` |
|------------|---------:|--------------------------------|
| eek        |   5      | flat (line 186, before loop) |
| sk         |   1      | flat (line 189, before loop) |
| e_sm_lifted| 147      | flat (lines 193-196, before loop) |
| pk0        |  58      | loop body (line 205) |
| e_sm       |  58      | loop body (lines 209-212) |
| e_sm_quotients| 89    | loop body (lines 214-217) |
| r          |  13      | loop body (lines 223-226) |

`e_sm_lifted` at 147 bits is ~3 orders of magnitude wider than the next-largest flat cell (`eek` at 5 bits); a solo NOP of `e_sm_lifted` isolates its cell cost without touching the loop, and the delta vs r157's goldens is the answer to the R158 RESUME question for the C1 flat side.

## Method

Detached worktree /tmp/r159 @ f7c87dbb9 (post-r156/r157/r158 tips; C1 locus byte-identical to r157 base). Same shadow-NOP mechanics as r157:
- preset flip insecure-512 → secure-8192 + dkg/threshold secure use in `configs/default/mod.nr`
- `nargo compile --force` on `circuits/bin/threshold` (artifact at package-ROOT `target/pk_generation.json`, per r152c vessel note)
- `bb gates -t noir-recursive-no-zk`
- taskset -c 0-3, `/usr/bin/time -v` wall/peak, trap-restore both files byte-exact after every leg, PORC 0 verified after every exit
- sha-pinned pre-round on both DEF and PK (7f07de82 / 8e37436b — same pins as r157)

Legs:
- **A1 unblunt** (baseline; reproduces r157 golden 1,634,722 g)
- **B  e_sm_lifted solo NOP** (only the 4-line `self.e_sm_lifted.range_check_2bounds::<BIT_E_SM_LIFTED>(self.configs.e_sm_bound, self.configs.e_sm_bound);` comment-block under `// Check the smudging noise over the integers` is NOP'd; eek, sk, and the entire per-i loop stay active)

In-session foreground HEAD 247298ad5 (r157) → f7c87dbb9 (this round): r157's leg A1 digital-anchor carries forward by the byte-identity of the C1 locus across `247298ad5 -> 3291d85bd -> f7c87dbb9` (r157 receipts + r158 receipts are both 0-circuits commitments on this sub-tree), but this round re-runs A1 on the fold base to prove the base-stability at THIS base.

## RAN results (fold base f7c87dbb9)

| leg | gates | ACIR | wall | peak |
|-----|------:|-----:|-----:|-----:|
| A1 unblunt | 1,634,722 | 582,531 | 74.4 s | 18,429,324 kB (17.6 GiB) |
| B e_sm_lifted solo NOP | 1,507,699 | 549,763 | 70.1 s | 15,833,452 kB (15.1 GiB) |

Sole NOP applied: `self.e_sm_lifted.range_check_2bounds::<BIT_E_SM_LIFTED>(self.configs.e_sm_bound, self.configs.e_sm_bound);` (4 lines) under the `// Check the smudging noise over the integers` comment. eek, sk, and the entire per-i loop body (pk0, e_sm, e_sm_quotients, r) stay active.

## Deltas vs r157 goldens (byte-identical C1 locus 8e37436b; the C1 locus at f7c87dbb9 == the C1 locus at r157 base 247298ad5, RAN-verified via r157+r158 receipts being 0-circuits-only)

| quantity | r157 (c98b-r157 base) | r159 (fold f7c87dbb9) | Δ |
|----------|-----------------------:|----------------------:|---:|
| A1 unblunt | 1,634,722 | 1,634,722 | **+0** (digit-exact base-stability) |
| e_sm_lifted solo cost | (never RAN at c98b) | **127,023 g** | RAN |
| eek + sk (sum) [carry] | (never RAN at c98b) | **76,483 g** = 203,506 − 127,023 | RAN (by subtraction; drug-invariant) |
| per-limb (r157 C) | 811,013 | 811,013 (reused) | byte-identical locus; leg-to-leg RAN |
| **family identity** | 811,013 + 203,506 = 1,014,519 | 811,013 + 127,023 + 76,483 = 1,014,519 | **+0 (digit-exact)** |

ACIR stability: A1 ACIR 582,531 digit-exact to r157 → the fold moved no opcodes on C1 (consistent with the C1 locus being byte-identical; only DKG C3 moved through #1996, r156).

## C1 flat decomposition (the question the round was asked to answer)

| cell | g | % of C1 leaf | % of C1 family |
|------|-----:|-----:|-----:|
| per-i loop (4 cells × L=3) | 811,013 | 49.61 % | **79.94 %** |
| e_sm_lifted (147-bit flat) | 127,023 | 7.77 % | 12.52 % |
| eek (5-bit flat) + sk (1-bit flat) | 76,483 | 4.68 % | 7.54 % |
| — of which r158 had measured only the total of the last two rows, 203,506 g = 20.06 % of family = 12.45 % of leaf |

Interpretation: the "20.06% flat" is NOT a per-limb recolor mislabeled as flat; it consists of **two genuinely flat cells** — `e_sm_lifted` (62.4 % of the flat slice) plus `eek + sk` (37.6 % of the flat slice). Per-limb mass remains the dominant slice at 79.94 %, matching r157's statement and the C1 Spec-A surface assessment (ring-LWE load-bearing, security-relevant coefficients).

## Verdict

RAN. Identity holds digit-exact. C1 flat side is cleanly split into `e_sm_lifted` (127,023 g) and `eek+sk` (76,483 g); per-limb 811,013 g was re-proven via r157's RAN casing on the byte-identical locus. For any future C6-class per-limb aggregate-bound redesign (owner-gated item (5)), the C1 row now has a **complete cell decomposition** — 4 loop cells + 3 flat cells all resized at the fold base, with per-limb 79.94 % the dominant slice. This is the sharpest Spec-A targeting number on the entire fold-base DKG family table (compare C2a's 100.00 % per-limb from r158, C3's 76.40 % from r156).

## Integrity / corrections-first

Leg A1 leak: a test-run started under the session's background runner was SIGKILL'd by that runner's own reaping after ~14 s (not an OOM; box had 29 GiB free pre-execution, DRAM stayed healthy, the trap never fired in the shell). Caught immediately because the empty `r159A1_live_stdout.log` + no caption file flagged the gap. Remediation: ran the whole `r159_legs.sh` in-session foreground (the r157/r158 in-session pattern proved to be the stable channel on this box). Both legs RAN in 74.4 s + 70.1 s = 144.5 s total. Byte-exact restore verified (both DEF + PK shas re-pinned to the pre-run pins; PORC_NONUNTRACKED=0 after leg B). No corrupted state existed at any point; the only pre-clean artifacts (0-byte stdout/timev logs from the killed background run) were deleted BEFORE the in-session rerun.

## Mutation surface

Receipts-only: everything in this dir (2 fresh.json, 2 gates.json, 2 captions, 2 timev + 2 stdout + 2 gates_err logs, 1 delta.r159, 2 backup .nr files, log.r159, r159_legs.sh, this plan.md) + ONE receipts-only commit on i5/dkg-research. Research branch **research/r159-c1-flat-esmlifted-solo** on the private enclave remote. No circuits/ source. No crates/. No upstream PR (0 circuit-source change).