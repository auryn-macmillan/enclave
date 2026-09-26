// SPDX-License-Identifier: LGPL-3.0-only
//
// r135 BPA — the 42-cell (H=14 x L=3) DIRECT-SHA producer-attest BLOCK at the
// production commit point. Exactly the r133 b1 shape (30-cell H=10) restated at
// the r134 post-upstream production shape (H=14, 42 cells): per (honest,
// modulus) slot the producer re-hashes the share through the REAL C4 verify
// sponge (compute_share_encryption_commitment_from_message) and pins each
// commitment to a pub cell (r131/np2 pin-protocol). This arm prices the
// "producer commit-and-attest ONCE, per share" route at block scale so it is
// like-for-like against h14_v0 - h14_v1 = 3,022,405 g (the consumer re-commit
// block it would displace, r134 RAN).
// Liveness: all 42 outputs are asserted against pub pins -> all sponges live.
// L=3 moduli per honest party; H from configs::committee::small via active
// flip (the flip sets committee/active to small: N_PARTIES=19, T=9, H=14).
use lib::configs::default::H;
use lib::configs::default::dkg::{L as L_THRESHOLD, N, SHARE_ENCRYPTION_BIT_MSG};
use lib::math::commitments::compute_share_encryption_commitment_from_message;
use lib::math::polynomial::Polynomial;

fn main(
    shares: [[Polynomial<N>; L_THRESHOLD]; H],
    expected: pub [[Field; L_THRESHOLD]; H],
) {
    for h in 0..H {
        for l in 0..L_THRESHOLD {
            let out = compute_share_encryption_commitment_from_message::<N, SHARE_ENCRYPTION_BIT_MSG>(
                shares[h][l],
            );
            assert(out == expected[h][l], "pin");
        }
    }
}