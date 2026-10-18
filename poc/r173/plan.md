# r173 — lane (i) V4-parity solo re-pin @ post-fold tip f4ee7b7a8

Owner armed 2026-10-18 ~13:35 EDT (verbatim): "(i) V4-parity solo re-pin leg:
ARMED = one solo-NOP + one unblunt leg at the current tip re-pinning the
~208,896 g parity cell (per r164/r170 numbering), completeness measurement
for the cost table." Priority order: after (iii) DRAFT (delivered r172),
(i) runs this round. The E1 unblunt leg doubles as the FIRST re-anchor datum
at the new secure-50-coeffs shape (#2195 fold, [LEAN-1215]).

## Method

Detached worktree /tmp/r173 @ f4ee7b7a8af1adf0006308b13c15d9ea04bd8411
(main checkout pr-2229 untouched). r163/r164-style shadow-NOP harness:
secure-8192 preset flip in configs/default/mod.nr (NEW anchor: upstream #2226
moved the default preset to insecure-64, so the flip string is
"insecure-64"->"secure-8192" — r163/r170 scripts' "insecure-512" string would
assert-fail at this base); V4 = whole verify_parity_check body comment-out in
share_computation.nr; DEF 17c3347e + SC 44eb78d7 sha-pinned, restored
byte-exact (post-run verified, tracked diff 0). Vessel: systemd-run --user
--slice=user.slice --property=MemoryMax=infinity escape (gateway-cgroup cap
lesson [LEAN-1215]); per-leg taskset -c 0-3 + /usr/bin/time -v; nargo compile
--force; bb gates -t noir-recursive-no-zk.

## Harness fixes found this round (both RAN, both receipts-preserved)

1. ARTIFACT PATH MOVED: upstream #2236 (zk artifact-CLI refactor) — nargo
   beta.26 emits bin artifacts to the WORKSPACE target dir
   circuits/bin/dkg/target/<pkg>.json, not the per-package target/ that
   r163/r170 used. First run: E1 compiled rc=0 wall 190.6 s but the script's
   `[ -s "$art" ]` checked the old path -> E1_FAIL. The attempt-1 artifact was
   RECOVERED from the workspace target dir (not recompiled): gates 2,586,565 /
   ACIR 854,722, sha256 66d88299...; receipt r173E1_attempt1_* preserved.
   Script fixed (TGT=$BIN/target); the re-run E1 (wall 192.4 s) reproduced the
   SAME gates/ACIR digit-exact (determinism cross-check).
2. V4 SPLICE: r164-style find(') {', i) is NOT safe for verify_parity_check —
   its doc-comment contains a call example ending `);` followed by an indented
   `{` two lines later (call sites L106/L183 pattern), so the naive search
   truncates the body-open BEFORE the real signature. Fixed by anchoring on
   the multi-line signature's first param line, paren-matching the signature,
   then brace-matching the body. (A first fix attempt also hit a
   `''.join`-vs-`'\n'.join` bug that collapsed the commented body onto one
   line — caught by dry-run + compile error at L300 before any wasted leg.)

## RAN (base f4ee7b7a8; digits from on-disk *_gates.json)

  E1  C2b unblunt (NEW shape)  = 2,586,565 g   ACIR 854,722   wall 192.4 s  peak 5,731,044 KB
  V4  parity solo NOP (NEW)    = 2,377,669 g   ACIR 707,266   wall 179.7 s  peak 5,459,848 KB

  V4 CELL (new shape) = E1 - V4 = 208,896 g   vs OLD r164 cell 208,896 g  -> DELTA 0 (digit-exact)
  E1 SHAPE SHIFT      = 2,586,565 vs OLD golden 2,586,563 -> +2 gates (+0.00008%)
  V4 share of leaf: 8.08% new vs 8.08% old (208,896/2,586,563)

## Verdict

RAN. The lane-(i) re-pin lands DIGIT-EXACT: the V4 parity cell is 208,896 g
at the new secure-50-coeffs shape, identical to r164 @ cb722eea281. The C2b
leaf E1 moved by only +2 gates across the entire #2195 param-set change
(PLAINTEXT_MODULUS 1e6->17e6, Q_MOD_T, E_SM/PK/CT0 bit widths all moved per
r172 blob-compare) — the leaf is essentially INSENSITIVE to the fold. This is
the first re-anchor datum and it says: the r172 "pool digits STALE" caveat is
quantitatively TINY for the C2a/C2b twins (family = the same
check_range_bounds fn, twin-invariant; ACIR digit-identical too). Remaining
staleness risk concentrates in C1 pk_generation + C3 share_encryption (the
leaves whose bit widths moved: PK 58->59, CT0_R 20->24) — unmeasured, that is
the natural follow-up if the owner wants the full re-anchor.

## Integrity

- Worktree /tmp/r173 final: tracked diff 0; DEF + SC restored byte-exact
  (sha re-verified post-run). Main checkout pr-2229 @ 7451101d4 + 5
  OTHER-session dirty lines UNTOUCHED all round.
- attempt-1 E1 artifact recovered, not recompiled; re-run reproduced it
  digit-exact (2 independent compiles, same gates/ACIR).
- Receipts: r173_legs.sh, log.r173, 2x *_fresh.json/_gates.json/_timev.log/
  _wall.raw/_stdout.log, r173_delta.r173, attempt-1 receipts.

UPSTREAM-PR: NONE (0 circuits/ + 0 crates/ delta; poc receipts only).