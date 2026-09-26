// SPDX-License-Identifier: LGPL-3.0-only
// b9: 30 sponges, self-assert each node (pub-ds loop, b3 shape)
use lib::math::commitments::compute_commitment;
fn main(
    s: pub [Field; 30],
    e: pub [Field; 30],
    ds: pub [u8; 64],
) {
    for c in 0..30 {
        let node = compute_commitment([s[c], e[c]], ds);
        assert(node + 0 == node, "selfref");
    }
}
