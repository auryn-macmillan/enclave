// SPDX-License-Identifier: LGPL-3.0-only
// r133 bnp-1: 30-cell grid, expected PRIV (non-pub) -> forces sponge reachability
use lib::math::commitments::compute_commitment;

fn main(
    sk_leaves: pub [Field; 30],
    esm_leaves: pub [Field; 30],
    ds: pub [u8; 64],
    expected: [Field; 30],
) {
    for c in 0..30 {
        let node = compute_commitment([sk_leaves[c], esm_leaves[c]], ds);
        assert(node == expected[c], "bind");
    }
}
