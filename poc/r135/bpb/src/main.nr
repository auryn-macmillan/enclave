// SPDX-License-Identifier: LGPL-3.0-only
//
// r135 BPB — the 42-cell (H=14 x L=3) MERKLE-NODE producer-attest BLOCK at the
// production commit point: the r133 a1 single-cell shape (build BOTH leaf
// commitments with the real per-share fn, then dilute into ONE SAFE node,
// pin node OUT) instantiated per (honest, modulus) slot = 42 cells. This is
// the "producer commits leaf + ONE node per cell, node pinned" route; the
// like-for-like contrast is BPA (direct-sha only, no node) and against
// h14_v0 - h14_v1 (the consumer re-commit block it would displace, r134 RAN
// 3,022,405 g). The node domain is the constant zero salt (B0-class); the
// per-cell pin keeps every node sponge live (np2 pin-protocol).
// H from configs::committee::small via active flip (H=14).
use lib::configs::default::H;
use lib::configs::default::dkg::{L as L_THRESHOLD, N, SHARE_ENCRYPTION_BIT_MSG};
use lib::math::commitments::{compute_commitment, compute_share_encryption_commitment_from_message};
use lib::math::polynomial::Polynomial;

fn main(
    sk_shares: [[Polynomial<N>; L_THRESHOLD]; H],
    esm_shares: [[Polynomial<N>; L_THRESHOLD]; H],
    expected: pub [[Field; L_THRESHOLD]; H],
) {
    let ds: [u8; 64] = [0x00; 64];
    for h in 0..H {
        for l in 0..L_THRESHOLD {
            let skc = compute_share_encryption_commitment_from_message::<N, SHARE_ENCRYPTION_BIT_MSG>(
                sk_shares[h][l],
            );
            let esc = compute_share_encryption_commitment_from_message::<N, SHARE_ENCRYPTION_BIT_MSG>(
                esm_shares[h][l],
            );
            let node = compute_commitment([skc, esc], ds);
            assert(node == expected[h][l], "pin");
        }
    }
}