// SPDX-License-Identifier: LGPL-3.0-only
// r133 b3 — 30-cell loop, PUB leaves, PUB ds (B0 + np2 pin-protocol).
use lib::math::commitments::compute_commitment;

fn main(
    sk_leaves: [Field; 42],
    esm_leaves: [Field; 42],
    expected: pub [Field; 42],
) {
    let ds: [u8; 64] = [0x00; 64];
    for c in 0..42 {
        let node = compute_commitment([sk_leaves[c], esm_leaves[c]], ds);
        assert(node == expected[c], "pin");
    }
}