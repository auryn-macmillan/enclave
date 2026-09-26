// SPDX-License-Identifier: LGPL-3.0-only
// b8: 2 sponges, self-assert (node + 0 == node) forces each node into the program
use lib::math::commitments::compute_commitment;
fn main(
    s: pub [Field; 2],
    e: pub [Field; 2],
    ds: pub [u8; 64],
) {
    for c in 0..2 {
        let node = compute_commitment([s[c], e[c]], ds);
        assert(node + 0 == node, "selfref");
    }
}
