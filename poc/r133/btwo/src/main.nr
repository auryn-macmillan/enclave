// SPDX-License-Identifier: LGPL-3.0-only
// btwo: EXACTLY 2 sponges (2-cell grid, pub leaves + pub ds + pub pins)
use lib::math::commitments::compute_commitment;
fn main(
    s: pub [Field; 2],
    e: pub [Field; 2],
    ds: pub [u8; 64],
    expected: pub [Field; 2],
) {
    for c in 0..2 {
        let node = compute_commitment([s[c], e[c]], ds);
        assert(node == expected[c], "pin");
    }
}
