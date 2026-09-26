// SPDX-License-Identifier: LGPL-3.0-only
//
// r133 B0 — the 30-cell (H=10 x L=3) MERKLE-NODE attestation block at PRODUCTION
// SCALE: the full re-instantiation of A1's single node (the r132-calibration shape:
// per-cell x30 vs full-block, where adjacent sponge instantiations may share pinned
// intermediate wires). Leaves are plain Fields (the commitment leaves the producer
// holds after the C2/C3 share commits); every node OUT is pinned to its pub cell ->
// all 30 sponges stay live (np2 pin-protocol). Cell pairing (sk_leaf, e_sm_leaf per
// (honest, modulus) slot) is a labeled counterfactual: it pins the gate shape, not a
// shippable scheme.
use lib::math::commitments::compute_commitment;

fn main(
    sk_leaves: [Field; 30],
    esm_leaves: [Field; 30],
    expected: pub [Field; 30],
) {
    let ds: [u8; 64] = [0x00; 64];
    for c in 0..30 {
        let node = compute_commitment([sk_leaves[c], esm_leaves[c]], ds);
        assert(node == expected[c], "pin");
    }
}