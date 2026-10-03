# r145 — C2a 58-bit per-coeff range family + combined-impact ranking

Owner's question (DIRECTION 2026-10-02): "biggest combined impact across DKG AND in-browser
input validation; my intuition is the per-coefficient range checks compete with, or beat, the
in-circuit sponge." This round prices that family and ranks both paths.

Form: out-of-tree shadow-compile in the r99/r100 shape, measurement-only — the per-coefficient
58-bit range-check call at `circuits/lib/src/core/dkg/share_computation.nr` line 102 (C2a
execute) is commented out, presets flipped to secure-8192, committee held at `minimum`
(N=3/T=1/H=2), compiled with `nargo`, gates read from the compiled JSON, then the tree is
restored byte-exact (configs shas re-verified, porcelain 0). NOT a sound vehicle — never
released, never shipped. Deliverable is the fraction + the ranking, only.

## Leg A — RAN (rep must match the golden before the Δ is quotable)

| Leg | Gates | ACIR ops | Wall (4-core) | Peak RSS |
|-----|-------:|---------:|--------------:|---------:|
| **A0** unblunted (re-anchor) | **1,446,311** | 426,360 | 2:37.09 | 4.53 GiB |
| **A1** range-NOP (line 102) | **893,346** | 205,176 | 2:30.40 | 4.55 GiB |

- **ΔGates = 1,446,311 − 893,346 = 552,965 g = −38.23% of the 1.446 M C2a base.**
  (ΔACIR = −221,184.)
- **Golden gate check PASS:** A0 reproduces the r45/r99/r100 byte-pinned golden 1,446,311
  digit-exact → zero shape drift on tip `82178f4d6` (rebase to `d62e22e` touched no `.nr`, so
  the golden holds on the new base).
- Fresh artifact SHA-256: A0 = `797ec6bc427ef5c2401d4e68ea2e34088d4584e9c31575a77d1842d0adc00075`,
  A1 = `9eef3c7e6bead00f7f1e5e16b75172da3dcc26f264bbe507ba1424b133a4fbe4`. Toolchain: nargo
  1.0.0-beta.26 / bb 5.1.0, box 8-core / ~31 GiB avail / 0 swap (2026-09-11 re-provision).
- Run vehicle: **systemd user unit** (MemoryMax=31G, taskset 0-3). An inline
  `terminal background=true` attempt OOM-killed at ~4 GiB in run-1 (nargo peaks above the
  worker-scope cap); the user-unit form is the proven r99 shape and both legs completed clean,
  tree restored byte-exact each leg.

Prove-wall read (DRAFT anchor, RAN-robust percentage): at the r81/r82 measured proving rate
(~10.3–10.9 µs/gate), a −38.23% gate cut on a leaf maps to a −38.23% proving-wall cut on that
same leaf at any rate (rate is RAN-fixed; only the gate count moves). No N=19 prod prove wall
was built this round; the % is the quotable quantity.

## Leg B — DRAFT-bounded ranking from existing RAN goldens (no recompile)

DKG leaf gate shares (min N=3, secure-8192, r45/r99/r100 byte-pinned sum = 11,558,499 g):

| Family | Gates | % of DKG | Range-family status |
|--------|-------:|---------:|---------------------|
| C3 | 2,966,353 | 25.66% | UNPRICED → #1 r146 target |
| C2b | 2,888,964 | 24.99% | UNPRICED → #2 r146 target (C2a twin) |
| C1 | 2,223,114 | 19.23% | UNPRICED |
| C4 | 1,746,030 | 15.11% | RAN rate exists (r141, +23.6× base-cell dense) |
| **C2a** | **1,446,311** | **12.51%** | **r145 RAN: per-coeff = 552,965 g (38.23% of C2a)** — tag-only (r34 load-bearing) |
| C0 | 287,727 | 2.49% | small |
| **Total** | **11,558,499** | 100% | |

Within C2a the measured cut is **552,965 g = 4.79% of the whole DKG base.** r34 already proved
the C2a 58-bit range family is **soundness-load-bearing** at secure-8192 (dropping it breaks
soundness), so 38.23% is a *fraction of a tagged family*, not a free lever. The actionable
lever, if we want a cut here at all, is a chip-level / per-word aggregate bound rather than a
per-coefficient check — same class as r115's C6 bulk tag (−13.943% RAN, owner-pending).

Browser P3 (r132 RAN, M3 cell = 71,981 g):

| Component | Gates | % of cell |
|-----------|------:|----------:|
| SafeSponge re-commit | 69,249 | **96.20%** |
| bit-decompose + flatten + ALL range checks + SZ (remainder) | 2,732 | 3.80% |

The per-coefficient range family is a *subset* of the 2,732 g remainder, so at P3 it is
**< 3.80%** of the cell — the in-circuit sponge dominates 25× over the whole remainder. The
owner's intuition ("per-coeff range beats the sponge") is **REJECTED for the browser path**.

## Final combined-impact ranking

Ranked by (i) verifiable reducible amount and (ii) viable security posture given the r144-closed
pin (no pin-binding substitute), across both paths:

1. **C3 per-coeff range family** — largest leaf (25.66% of DKG), range family yet UNPRICED.
   Single biggest candidate reducible amount; ablate it next (same Leg-A form, ~2:30 wall).
   DRAFT: if its range share mirrors C2a's 38.2%, max cut ≈ 1.14 M g ≈ 9.8% of DKG.
2. **C2b per-coeff range family** — 24.99% of DKG, C2a twin, UNPRICED; do it in the same
   r146 round (leg-B staged for the twin, `poc/r145/B.sh`).
3. **C1 range family** — 19.23%, UNPRICED, same shape as #1/#2 (r147).
4. **C2a per-coeff family** — RAN this round at 38.23% of C2a but **tag-only** (r34
   load-bearing). Will revert; only recoverable via an aggregate-bound redesign (r115 C6 class).
5. **C4 dense per-coeff range** — RAN rate from r141 (+23.6× base-cell); on the production C4
   shape the absolute cut is smaller than #1's projected ceiling, so it ranks below.
6. **Browser P3 remainder (<3.80%)** — small; not a diluting target at P3. The P3 win, if any,
   is in the 96.20% SafeSponge re-commit (r113 large-end re-commit 84.46% is the known lever),
   not in the range family.

**Recommendation:** run r146 as a two-leg shadow-NOP on **C3** and **C2b** (same r99 form,
~2:30 wall each, same box-safe unit). That converts the two UNPRICED leaves that sum to 50.7%
of the DKG base into measured fractions in one round, and tells us whether the per-coeff
family is genuinely the DKG-hour blocker (as #1 for the owner is now C3).

UPSTREAM-PR: none. This round is measurement-only; the innocuous tree targets were restored
byte-exact (porcelain 0, config shas 7f07de82 / 0bf0cc64 / df7c32c5), and the diff on the
review branch is poc/-only. A future r146 + C3/C2b ablation could feed a prototype / upstream
PR candidate, but that would need the owner's sign-on and a soundness argument, not this
round's bytes.