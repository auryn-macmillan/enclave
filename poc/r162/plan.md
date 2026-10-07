# R162 source-read receipt: C3 narrow-flat solver-fold (REFUTED at source level)

# r162 plan

Idea: R161's DRAFT#4 — the e1 = exactly-half-of-e0 step and the non-additive 73,728 g gap were explained by "a bound-key or sibling-fold dedup in range_check_2bounds." This is the R161 resume note's p1: a 5-min source read (0 compile) discriminates bound-key vs bound-value reading. Crates scope: ZERO source edits this round, only a plan.md receipt + line anchors.

Method
- Source: circuits/lib/src/math/polynomial.nr, lines 173-182 (range_check_2bounds body), lines 142-165 (doc).
- Caller: circuits/lib/src/core/dkg/share_encryption.nr lines 442-444 (u, e0, e1 call sites), lines 129-136 (Polynomial<N> decl, all three same length).
- Config: circuits/lib/src/configs/secure/dkg.nr lines 72-74 (BIT_U=1, BIT_E0=5, BIT_E1=5); circuits/bin/config/src/main.nr lines 199-209 (u_bound=1, e0_bound=20, e1_bound=20) — RAN grep in prior round, cited unchanged.
- The three u/e0/e1 calls are a generic pass `<let BIT: u32>` (no value-generic), so the only per-call variation is the (BIT, lower_bound, upper_bound) tuple; N is the shared polynomial length for all three.

**FINDING 1 (RAN, grep + read lines 173-182, 442-444):** `range_check_2bounds` is a *generic* function (no poly-id tag, no per-tag specialization, no tag-allocator). Its entire body is a loop over `0..self.coefficients.len()` with (per iter) one shift `self.coefficients[i] + lower_bound`, one constant `range_size - shifted`, and two `assert_max_bit_size::<BIT+1>` asserts (lines 179-180). The only per-call parameters are (BIT, lower_bound, upper_bound).

**FINDING 2 (RAN, cross-check source pins):** u and e0 have DIFFERENT (BIT, bound) tuples: (BIT_U=1, (1,1)) vs (BIT_E0=5, (20,20)). e0 and e1 are BYTE-IDENTICAL in every observable param: (BIT_E0=BIT_E1=5, (20,20), N=8192). So the source admits NO identity-key on u-e1 that would predict e1 = half-e0.

**FINDING 3 (RAN arithmetic on R161 digits):** If all three calls had equal per-cell cost, X would be ≈ 3 × 73.7k ≈ 221k. Measured (RAN, R161) X = 110,612 = 73,733 + 36,864 (u + e1 only; e0's cell is absorbed). So the three cells sum to 184,340 but X only removes 110,612 — one full cell (≈ e0-sized 73,743) of over-count. The interpretation "one cell is folded into a sibling" is DRAFT; the equality X = full + half is RAN.

**FINDING 4 (RAN, grep-verbatim of the config lines):** `circuits/lib/src/configs/secure/dkg.nr` L72-74 are `pub global SHARE_ENCRYPTION_BIT_U: u32 = 1;` / `pub global SHARE_ENCRYPTION_BIT_E0: u32 = 5;` / `pub global SHARE_ENCRYPTION_BIT_E1: u32 = 5;`. `circuits/bin/config/src/main.nr` L199-201 bind `let u_bound: u128 = SHARE_ENCRYPTION_U_BOUND as u128;` (+ the E0/E1 equivalents); L203/206/209 comments name u_bound as 1 (ternary) and e0/e1_bound as 20. So the three SE L442-444 call sites see (BIT=1,(1,1)) / (BIT=5,(20,20)) / (BIT=5,(20,20)).

**VERDICT (RAN, source-read only, 0 compile, 0 rust touched):** DRAFT#4's "bound-key in the specializer" is REFUTED for the source level. There is no bound-key, no per-tag specialization in `range_check_2bounds`. The e1 = half-of-e0 and the 73,728 non-additive gap are CLEAN at the source boundary, meaning the fold happens strictly above the emitter (the solver's CSE, or Cranelift-equivalent recompile-reallocation that happens when Noir lowers asserts to gates). Any LEVER along the DKG narrow-flat should model the whole X slot (110,612 g), not the three cells (gap 73,728 g = one cell over-counted), consistent with R161's finding (5).

**Next (p2, NOT this round):** To discriminate the two remaining backend sub-mechanisms (solver common-subexpression vs emit-time lowering pattern), the clean probe is a single 1-leg swap run: temporarily flip which of e0/e1 is emitted first at SE L443-444 (recompile only, no protocol change) and observe whether e1's half-cost tracks the *call order* (=> lowering/emit pattern) or tracks the *symbol e1* regardless of order (=> solver-level). Not run here (a fresh leg, ~3-4 min wall) so it is DRAFT. The narrow-flat verdict is closed either way: model X = 110,612 g, not the 3-cell sum.

## Verdict (RAN source-read, 0 compile, 0 rust / 0 .nr / 0 .rs touched)

**Claim: REFUTED at the source level; RE-SCOPED to the solver/backend (DRAFT).** R161 pinned as "a bound-key or sibling-fold dedup in `range_check_2bounds`." Reading the body (polynomial.nr L173-182: generic `<let BIT: u32>`; the loop at L176; the two asserts at L179-180; `range_size = lower_bound + upper_bound` at L174) shows: **no poly-id tag, no per-tag specialization, no bound-key, no sibling-fold, no dedup code path.** u / e0 / e1 instantiate the same `Polynomial<N>` (SE L130/134/136) and call the same generic (SE L442-444). The only per-call differences are (BIT, lower_bound, upper_bound) = (1, 1, 1) / (5, 20, 20) / (5, 20, 20), which means e1 and e0 are BYTE-IDENTICAL in every observable param. So e1 = half of e0 is NOT decided at source level. The fold that makes X (110,612 g, R161 RAN) less than the 3-cell sum (184,340 g, gap 73,728 g) happens **above the source boundary** — in the Noir solver's gate allocation / Cranelift-style re-allocation when `assert_max_bit_size` lowers to gates. Whether it is solver-CSE or lowering-pattern-key on the emit side is DRAFT (undiscriminated, needs a single extra leg in the r161 A1 spot if the owner wants it).

**Rule of thumb for any future C3 narrow-flat lever:** model the whole X slot (110,612 g, RAN R161) not the three cells (sum 184,340 g over-counts by one e0-sized cell, 73,728 g). Consistent with R161's FINDING 5.

## RAN source pins (this round, re-verified on disk)
- circuits/lib/src/math/polynomial.nr: L173 `pub fn range_check_2bounds<let BIT: u32>(self, upper_bound: Field, lower_bound: Field)`; L174 `let range_size = lower_bound + upper_bound;`; L176 `for i in 0..self.coefficients.len()`; L177 `shifted = self.coefficients[i] + lower_bound`; L179-180 the two `assert_max_bit_size::<BIT+1>()` asserts.
- circuits/lib/src/core/dkg/share_encryption.nr: L130/134/136 u/e0/e1 all `Polynomial<N>`; L442-444 the three `range_check_2bounds` call sites.
- circuits/lib/src/configs/secure/dkg.nr: L72 BIT_U=1 / L73 BIT_E0=5 / L74 BIT_E1=5.
- circuits/bin/config/src/main.nr: L199-201 u_bound/e0_bound/e1_bound bindings (L203/206/209 comments: 1 / 20 / 20).

## RAN gate
- 0 .rs / 0 .nr / 0 .rs source edits (source read only). `cargo check --workspace` rc 0 (3.61 s warm, this round).
- LOCUS share_encryption.sha256 = 308c8c5d (767 L) BYTE-FREEZE unaffected (no source touched).
- origin/main = f2df52907 UNMOVED; HEAD = 9d4a86352 before commit; EB c98b0d1caa31 LOCKED.
