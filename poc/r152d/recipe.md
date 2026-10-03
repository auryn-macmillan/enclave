# r152d — C2a + C2b re-anchor + range shadow-NOP + C4 re-confirm @ new base c98b0d1ca

ONE idea: close the per-leaf re-anchor table opened by #1999 (`bound openings, quotients and
VK trees`, rewrite of share_encryption.nr +509/-139, share_computation.nr +149/-35,
configs/{insecure,secure}/dkg.nr +35/-16) for the two C2 twins and C4. r152b landed C3,
r152c landed C1; this round lands C2a, C2b, C4 on the SAME new base c98b0d1ca so the
C1+C2a+C2b+C3 range-family pool and the full new-base denominator are both RAN.

## Method (r145/r146 twin form, measurement-only, NEVER shipped)
Detached worktree /tmp/r151b @ c98b0d1ca (porcelain 0 pre+post), two systemd user units
(MemoryMax=31G, taskset -c 0-3, Restart=no): `r152d_c22b` (4 legs) + `r152d_c4` (1 leg).
For every leg: preset flip (insecure-512 -> secure-8192, N=3/T=1/H=2/L=3 secure-8192/minimum),
compile with `taskset -c 0-3 nargo compile --force`, gate with
`bb gates -b <fresh artifact> -t noir-recursive-no-zk`, sum `functions[].circuit_size`,
capture FRESH_SHA256, then restore the tree byte-exact (config + in-tree JSON both pinned).

C2a/C2b both invoke the same call site, so the two NOPs are distinguished by OCCURRENCE
index in share_computation.nr (1st = C2a body @ line 103 = `SecretKeyShareComputation.execute`;
2nd = C2b body @ line 180 = `SmudgingNoiseShareComputation.execute`). The splice is
string-matched on the full call (count==2 assert), not by raw line number, so it is
stable across a re-compile.

Leg -> gates (RAN):
  A2A C2a unblunt      1,464,743
  A2B C2b unblunt      2,586,563
  B   C2a 1st-NOP        911,778
  C   C2b 2nd-NOP      2,033,598
  C4  share_decryption unblunt 1,098,865

Deltas (RAN, additive):
  C2a family = A2A - B       = 552,965 g  (37.75% of C2a leaf)
  C2b family = A2B - C       = 552,965 g  (21.38% of C2b leaf)
  C2a+C2b    = 1,105,930 g
  C4 single leaf (no family) = 1,098,865 g

## Load-bearing finding
The per-node `check_range_bounds::<N, L, N_PARTIES, BIT_SHARE>` call-site is BASE-INVARIANT:
552,965 g at the NEW base c98b0d1ca == digit-identical to the OLD base d62e22e value that
r145/r146 measured. The C2a/C2b twins are the flat case; C3 shrank -35.97% (r152b) and
C1 grew +14.31% (r152c) across the same base shift. Consequence for the in-tree C6-class
(Spec-A aggregate-bound) redesign: its per-twin ceiling does NOT need re-measurement at the
new base — the family is unchanged. Only the LEAF that the family is a fraction-of moved.

C4 range-ABSENCE (r150 kill) RECONFIRMED at the new base: 0 `range_check` in
share_decryption.nr and 0 in math/commitments.nr (which now hosts the C4-only helpers
compute_aggregated_shares_commitment + compute_share_encryption_commitment_from_message under
#1999, previously in share_decryption.nr). The kill is a function-of-cone fact, not a
file-path fact, so it survives the rebase.