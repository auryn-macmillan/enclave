// SPDX-License-Identifier: LGPL-3.0-only
//
// r133 B1 — the 30-cell (H=10 x L=3) DIRECT-SHA attestation block at PRODUCTION
// SCALE: B0's shape twin with the node replaced by the per-cell REAL share-commitment
// sponge (compute_share_encryption_commitment_from_message, the C4-verify unit,
// r132 p4). This arm prices "the producer re-hashes every share in-circuit" at the
// same 30-instantiation scale, so B0 vs B1 is a like-for-like binding-shape delta
// (the r132 1.70x prediction tested at block scale, not single-cell scale).
use lib::configs::default::dkg::{N, SHARE_ENCRYPTION_BIT_MSG};
use lib::math::commitments::compute_share_encryption_commitment_from_message;
use lib::math::polynomial::Polynomial;

fn main(
    shares: [[Polynomial<N>; 3]; 10],
    expected: pub [[Field; 3]; 10],
) {
    for h in 0..10 {
        for l in 0..3 {
            let out = compute_share_encryption_commitment_from_message::<N, SHARE_ENCRYPTION_BIT_MSG>(
                shares[h][l],
            );
            assert(out == expected[h][l], "pin");
        }
    }
}