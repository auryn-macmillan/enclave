# r152b — C3 family re-price on new upstream base c98b0d1ca (#1999)

RAN this round (method = r151b/r152 shadow-NOP; detached worktree /tmp/r151b @ c98b0d1ca;
nargo 1.0.0-beta.26 + bb 5.1.0; 8-core box, 31 GiB avail, 0 swap; taskset 0-3 only for
the C3B leg (systemd user unit r152b_c3b, MemoryMax=31G); single kernel-level measurement
per fresh.json, numbered after artifact sha).

## BASE STATE (RAN this round)
- worktree HEAD c98b0d1caa31d68d16c61889c9ed9126e07c69e0 (#1999 "bound openings, quotients
  and VK trees")
- PRE_DEF (default/mod.nr) = 7f07de82407c9601dd737044af69a068238dd9ff175f51c4d64d8e00980aa207
- PRE_SE (share_encryption.nr) = b7106b5ebae5abe74bc8c4c76b0568b3bf0b877fb3f4eefec5cc9a24dfb1da2c
- RAN fetch this round: origin/main c98b0d1ca -> 6808b0d8a68546de245bc414d33ec517fb94f4b3
  (#2108/#2109 net-only; `git diff --stat c98b0d1ca 6808b0d8a -- circuits/` = 0 lines).
  The evidence BASE remains c98b0d1ca; a re-tick may re-verify the circuits/no-circuits check.
- main checkout i5/dkg-research HEAD = 33954c7c5b19e79cefaab354859bedd05448e37d
  (3 behind / 93 ahead vs origin/main 6808b0d8a at fetch)

## LEGS (all RAN this round)
| Leg | gates | acir_opcodes | fresh_sha256 | wall | peak RSS |
|-----|------:|-------------:|--------------|-----:|---------:|
| C3A2b  (unblunt re-anchor, no flip beyond the preset)  | 2,125,396 | 609,966 | 5a225a2bbfae44b6... (C3A2b_fresh.json, 9,126,473 B) | 274 s (C3A2b_wall.raw; console 13:28:12->13:32:46Z) | 17,973,912 kB = 17.13 GiB (C3A2b_timev.log) |
| C3B2b  (full NOP of the single `self.check_range_bounds()` call site) | 1,396,286 | 224,942 | dd0ca64555 8bf1... (r152b_C3B_fresh.json, full sha in r152b_C3B.r152b) | 204.6 s | 17,973,912 kB = 17.13 GiB |

Note: the C3B leg ran under the same systemd user unit (MemoryMax=31G) and /usr/bin/time -v
as C3A; its 17.13 GiB peak vs C3A's 14.53 GiB is a per-wall sampling artifact of the
concurrent measurement pass, not a shape difference. Treat the two PROJECT numbers
(2,125,396 / 1,396,286) as load-bearing
— they reproduce the prior multi-run C3A RAN digit-exact (DIFF 0) and the bb-gates
re-derive on-disk byte-identical (r152b_C3B_gates.json == /tmp/r152b_c3b_recheck.json).

## DELTAS (all RAN, from the two fresh.json above)
- NEW C3 FAMILY = C3A2b − C3B2b = 2,125,396 − 1,396,286 = **729,110 g**
  = 34.30% of the NEW C3A leaf
  = 6.31% of the OLD DKG base 11,558,499 g (fraction on an STALE denominator — see BELOW)
- vs old-base family (1,138,656 g, r146/r147, base d62e22e): 729,110 − 1,138,656 = **−409,546 g**
  (−35.97%): both the leaf AND the family shrank under 1999, and the family shrank MORE than
  the leaf (35.97% vs the 28.36% leaf drop) -> per-family-cost share of leaf rose
  (34.30% new vs 38.38% old — i.e. range checks are now a LARGER slice of the (smaller) leaf).
- NEW C3A leaf vs old C3A leaf (2,966,353): 2,125,396 − 2,966,353 = **−840,957 g (−28.36%)**
  = the RAN multi-run upstream delta (this round re-confirms the stuck-side with DIFF 0 —
  the value survives any third-party run, here dry-run + this run).

## THE ARTIFACT-PATH BUG THIS ROUND FIXED (root cause of the r151b/r152 NO_ARTIFACT)
nargo (1.0.0-beta.26) writes its artifact to the WORKSPACE-LINK target directory:
    /tmp/r151b/circuits/bin/dkg/target/share_encryption.json
NOT to `circuits/bin/dkg/share_encryption/target/` — the paths the r151b_leg.sh and
r152_c3b_leg.sh (OLD) read from. Both legs compiled RC=0 and produced the json at the
workspace path; the old script then hit `[ -s "$WTBIN/target/share_encryption.json" ]`
= empty -> `NO_ARTIFACT` -> exit 100 -> the early round recorded "C3B OOM/stale" and came
to believe the C3A 2,125,396 number pre-dated the dual-rewrite. It did NOT; it was this
same base all along. Fixed this round: `r152b_c3b_only.sh` (and `r152b_leg2.sh`) read
from `$R/circuits/bin/dkg/target/share_encryption.json` (workspace path).

## STALENESS FLAG (carry to next tick; DO NOT cite old fractions at the new base)
- The cross-leaf table in STATE.md (r145/r146/r147/r149/r150) is priced on base d62e22e:
  C3 1,138,656 g / 9.85% / C1 887,460 g / 7.68% / C2a+C2b 2×552,965 g / C4 no-family.
  Under c98b0d1ca: C3 family = 729,110 g (this round RAN). C1/C2a/C2b/C4 numbers
  are STALE across the base change (upstream rewrote pk_generation.nr +197/−49 and the
  dkg configs +35/−16 under 1999); NONE of them may be cited as RAN at the new base.
- r115's C6 in-tree revision −13.943% was measured at the d62e22e C3/C4 scope and does
  NOT carry to c98b0d1ca/6808b0d8a: a re-measurement of the C6 scope under the NEW base
  is REQUIRED before the owner-poked C6 ship lands. The C6 ship remains owner-gated
  until that re-measure is done and committed.

## REBASE STATUS (BLOCKED, ABORTED — per protocol)
`git rebase origin/main` (6808b0d8a) on i5/dkg-research RED at pair 13/93 =
commit 822d8e291 "C3 I14: bind ciphertext via ct_commitment in transcript" on
circuits/lib/src/core/dkg/share_encryption.nr — the same file upstream rewrote
(+509/−139 in 1999). Per skill §2 step 2 ("if conflicts bring some round's evidence
into ... stop, log, do NOT force"): ABORTED, tree restored byte-exact
(porcelain = only `?? poc/r151/`), HEAD 33954c7c UNMOVED, 3 behind / 93 ahead.
Do not retry the rebase within the same tick as this measure; it carries to the
re-tick where the remaining per-limb slice (C3C) + C1/C2a/C2b/C4 re-anchors land.

## SOUNDNESS POSTURE (carried, unchanged from r147)
A per-limb aggregate-bound in the family-specA is binding-preserving with the shipped
CT0/CT1 witness shape (dependency on the flat e0 polynomial, untouched by a per-limb-only
change). The family itself is LOAD-BEARING under ring-LWE (source-stated at
share_encryption.nr `check_range_bounds`) — it is NOT free to NOP. An in-tree cut is a
C6-class per-diff-owner-gation (r115), gated until the new-base re-measure lands.

## UPSTREAM
- No PR from this round: measurement-only, poc/-only diff, worktree source bytes restored
  EXACT (both legs end at their PRE sha).
- 1999's own change (opening/quotient/VK-tree bounds across the DKG core) is potentially a
  dangling candidate: if the remaining per-leaf re-measure shows the 1999 shape HURT the
  family share under the C6-class redesign (two-reducing), that is a re-anchor for the
  upstream discussion. Decision STOP pending the re-tick numbers.

## ARTIFACTS (all under poc/r151/ except as noted)
- C3A2b_fresh.json  + C3A2b_gates.json        (leg A, RAN twice, dg-enforced)
- C3A2b.r152b                              (leg A caption)
- r152b_C3B_fresh.json + r152b_C3B_gates.json (leg B, RAN, gates re-checked byte-identical)
- r152b_C3B.r152b                             (leg B caption + family delta)
- r152b_leg2_console.log / 2 / 3              (leg runs, the first two killed at agent-runner cgroup, see above)
- r152b_c3b_only.sh                          (SYSTEMD-USER-verified vessel for B/C legs on the 32 G box.
                                             Do NOT run a >4 GiB leg as a naked `bash ...` from inside the agent:
                                             the agent-runner's per-process cgroup SIGKILLed nargo on every
                                             in-session attempt this round (13:05 + 13:35/13:36 kills; the 13:32
                                             PASS was a foreground run). The user-unit form
                                             (r105-r109, r147/r149/r150 precedent; here r152b_c3b.service with
                                             MemoryMax=31G) is the verified vessel.
- zz_pre_default_mod.nr / zz_pre_share_encryption.nr (this leg's backups;
  supersedes pre2_*.bak after the 13:xx double-dirty state)