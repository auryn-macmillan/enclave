// SPDX-License-Identifier: LGPL-3.0-only
//
// r132 P2 rev: per-limb pub pin on each element of the reversed vector.
use lib::configs::default::dkg::N;
use lib::math::polynomial::Polynomial;

fn main(
    share: Polynomial<N>,
    expected_rev: pub [Field; N],
) {
    let mut reversed_coeffs: [Field; N] = [0; N];
    for i in 0..N {
        reversed_coeffs[N - 1 - i] = share.coefficients[i];
    }
    for i in 0..N {
        assert(reversed_coeffs[i] == expected_rev[i], "rev pin");
    }
}