// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
//
// r131 node-cost probe B: ONE three-element SAFE commitment (node hash WITH depth salt —
// the conservative Merkle node model). Same output-pin protocol as np2 (see np2 header).
use lib::math::commitments::compute_commitment;

fn main(left: pub Field, right: pub Field, salt: pub Field, ds: pub [u8; 64], expected: pub Field) {
    let c = compute_commitment([left, right, salt], ds);
    assert(c == expected, "pin");
}