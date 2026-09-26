// SPDX-License-Identifier: LGPL-3.0-only
// r133 b2 — np2-parity loop control: 10 cells, pub leaves, CONSTANT ds
// (only loop/array form differs from r131 np2).
use lib::math::commitments::compute_commitment;

fn main(
    sk_leaves: pub [Field; 10],
    esm_leaves: pub [Field; 10],
    expected: pub [Field; 10],
) {
    let ds: [u8; 64] = [0x00; 64];
    for c in 0..10 {
        let node = compute_commitment([sk_leaves[c], esm_leaves[c]], ds);
        assert(node == expected[c], "pin");
    }
}