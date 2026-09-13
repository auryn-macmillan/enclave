// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
//
// r131 node-cost probe A: ONE two-element SAFE commitment (the Merkle-grid node-hash shape).
// The output is PINNED to a second pub input (assert == `expected`) — a pub output with no
// asserting constraint gets its whole sponge elided by Noir's constraint optimizer
// (observed: 96 gates with the pin removed; the pin is what keeps the sponge alive, exactly
// as in production where the commitment is asserted against an expected value).
use lib::math::commitments::compute_commitment;

fn main(left: pub Field, right: pub Field, ds: pub [u8; 64], expected: pub Field) {
    let c = compute_commitment([left, right], ds);
    assert(c == expected, "pin");
}