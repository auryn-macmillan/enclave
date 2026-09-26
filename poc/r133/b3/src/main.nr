// SPDX-License-Identifier: LGPL-3.0-only
// r133 b3 — 30-cell loop, PUB leaves, PUB ds (B0 + np2 pin-protocol).
use lib::math::commitments::compute_commitment;

fn main(
    sk_leaves: pub [Field; 30],
    esm_leaves: pub [Field; 30],
    ds: pub [u8; 64],
    expected: pub [Field; 30],
) {
    for c in 0..30 {
        let node = compute_commitment([sk_leaves[c], esm_leaves[c]], ds);
        assert(node == expected[c], "pin");
    }
}