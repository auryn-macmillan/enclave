// SPDX-License-Identifier: LGPL-3.0-only
//
// r135 V2B — the 42-cell (H=14 x L=3) MERKLE-NODE producer-attest BLOCK,
// corrected L (see v2/src/main.nr: leg-1 bpb had the same L=2 import defect;
// it compiled at 28 cells / 143,640 g/cell = 4,031,936 g). r133 a1 shape
// per (honest, modulus) slot: the producer commits BOTH share cells (sk +
// e_sm) with the REAL per-share fn, then dilutes the two commitment leaves
// into ONE SAFE node (B0-class constant-zero domain salt) and pins the
// node OUT (np2 pin-protocol; every node sponge stays live). Isolated
// per-cell twin = r133 a1 = 164,484 g (H-independent RAN class).
// Like-for-like contrast: V2 (direct-sha, no node) and the consumer re-commit
// block h14_v0 - h14_v1 = 3,022,405 g (r134 RAN, 42-cell).
use lib::configs::committee::active::H;
use lib::configs::default::dkg::{N, SHARE_ENCRYPTION_BIT_MSG};
use lib::configs::secure::threshold::L;
use lib::math::commitments::{
    compute_commitment, compute_share_encryption_commitment_from_message,
};
use lib::math::polynomial::Polynomial;

fn main(
    sk_shares: [[Polynomial<N>; L]; H],
    esm_shares: [[Polynomial<N>; L]; H],
    expected: pub [[Field; L]; H],
) {
    let ds: [u8; 64] = [0x00; 64];
    for h in 0..H {
        for l in 0..L {
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