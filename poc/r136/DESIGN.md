# r136 DESIGN (I18/I19 consumer cheap-verify swap)

Scope: design + safety proof sketch ONLY, per 2026-09-12 sign-off.
No circuits/crates source edit this round. Upstream base 51fa7415.

## RAN safety check (leg_b.py, in-tree, rc=0, seconds)
File: poc/r136/leg_b.py. Stdout: RAN.out.
Finding: pin(v) = 0 for v[N-2]=1, v[N-1]=-A mod P.

The r132/p3-class running-acc pin (`acc = acc*ALPHA + c[i]` line in
compute_share_encryption_commitment_from_message) is a LINEAR functional over
the circuit field, so kernel dim = N-1 (independent of prime). The acc-pin
ALONE is NOT collision-resistant and NOT the binding. The binding is the
co-enforced PIN FAMILY: (a) C2 affine parity pin, (b) C2 range pin on the
coefficients, (c) C4 verify_commitments call, and the acc-pin as a summed
linear reduction of the message. To drop the 71,981 g/cell S-sponge re-commit
(cut -96.17%) the consumer must keep every other pin live on its path.
Option B is a BINDING REARRANGEMENT, not a hash swap.

## Design consequence (scope of the in-tree diff, awaiting owner re-gate)
Producer side: direct-sha arm. r135 v2 RAN = 1.000020x consumer TIE (not the
Merkle arm, that one is 2.00102x, r135 v2b consumer 1.000020x pair 2.00102x).
Consumer side: ADD the acc-pin path in addition to the range + parity pins,
so C4 runs it once and does NOT redo the full per-cell S-sponge re-commit.
The real cost floor (RAN): 42 cells x 2,749 g (r132 p3-class) = 115,458 g
(DRAFT projection at in-block H14, per-cells in-block fit 0.026% r132-calibrated)
versus 3,022,405 g (r133/r135 A-block) = -96.17% (RAN floor, DRAFT for the
in-block consumer variant assembly).

## Invariant rows preserved
- C2 parity/affine pin: unchanged
- C4 verify_commitments call: unchanged
- C5 untouched
- A-row family (02-CRYPTO_CIRCUITS.md): all preserved
- pk_aggregation / PkAggregation structure: unchanged (r134 verified)

## Failure mode this RAN (leg_b) calls out
Any single co-pin drop on the consumer path breaks the binding fully. This
is the security-level constraint for the next in-tree diff (r137+ owner
re-gate).