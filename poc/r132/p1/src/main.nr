// SPDX-License-Identifier: LGPL-3.0-only
//
// r132 P1 (FLOOR): no production computation; pub pin only.
// Isolates base cost; every other delta is measured against this Art.
use lib::configs::default::dkg::N;
use lib::math::polynomial::Polynomial;

fn main(
    share: Polynomial<N>,
    expected: pub Field,
) {
    assert(share.coefficients[0] == expected, "pin");
}