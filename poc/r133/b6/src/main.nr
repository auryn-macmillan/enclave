// SPDX-License-Identifier: LGPL-3.0-only
// r133 b6 — UPPER BOUND: same 30-leaf depth-5 tree as b5 but EVERY interior
// node pinned to a pub input (all 31 interior nodes live-by-pub):
//   16 (l1) + 8 (l2) + 4 (l3) + 2 (l4) + 1 (root) = 31.
// b6 - b5 = the gate cost the unconstrained-interior version (b5, root-only pin)
// avoids, if any. Safe buffer is the sum of the 62 sponges; b5 decides what
// the ship shape actually costs.
use lib::math::commitments::compute_commitment;

fn main(
    leaves: pub [Field; 30],
    ds: pub [u8; 64],
    expected: pub [Field; 31],
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
    for p in 0..16 { assert(l1[p] == expected[p], "n1"); }
    for p in 0..8 { assert(l2[p] == expected[16 + p], "n2"); }
    for p in 0..4 { assert(l3[p] == expected[24 + p], "n3"); }
    for p in 0..2 { assert(l4[p] == expected[28 + p], "n4"); }
    assert(root == expected[30], "root pin");
}