// SPDX-License-Identifier: LGPL-3.0-only
// r133 bnp-2: depth-5 30-leaf tree, PRIV root expected (non-pub) -> live chain
use lib::math::commitments::compute_commitment;

fn main(
    leaves: pub [Field; 30],
    ds: pub [u8; 64],
    expected_root: Field,
) {
    let mut l0: [Field; 32] = [0; 32];
    for i in 0..30 { l0[i] = leaves[i]; }
    let mut l1: [Field; 16] = [0; 16];
    for p in 0..16 { l1[p] = compute_commitment([l0[2*p], l0[2*p+1]], ds); }
    let mut l2: [Field; 8] = [0; 8];
    for p in 0..8 { l2[p] = compute_commitment([l1[2*p], l1[2*p+1]], ds); }
    let mut l3: [Field; 4] = [0; 4];
    for p in 0..4 { l3[p] = compute_commitment([l2[2*p], l2[2*p+1]], ds); }
    let mut l4: [Field; 2] = [0; 2];
    for p in 0..2 { l4[p] = compute_commitment([l3[2*p], l3[2*p+1]], ds); }
    let root = compute_commitment([l4[0], l4[1]], ds);
    assert(root == expected_root, "root-bind");
}
