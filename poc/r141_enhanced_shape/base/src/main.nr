// SPDX-License-Identifier: LGPL-3.0-only
//
// r137 W6 - K-cell consumer cheap-verify slope probe (r132 p3-class body:
// reversed -> flatten BIT=58 -> running-acc pin, SAFE sponge DROPPED), the
// per-cell instantiation form the r135 leg-3 OOM diagnosis dictated. K in
// (6,12,42) probes the gate AND memory slope at the A production shape
// (secure-8192 N=8192, BIT_MSG=58) under the r135 DKG-preset-only flip
// (committee stays minimum; bare cell-count literals, no committee flip).
// RAN purpose: (a) 2-point gate linearity -> RAN-extrapolate the 42-cell
// (a)-block gate vs r136 DRAFT 42 x 2,749 = 115,458 g; (b) memory pivot so
// the 42-cell OOM cell count is a membrane fact, not a bug.
use lib::configs::default::dkg::{N, SHARE_DECRYPTION_BIT_MSG};
use lib::math::helpers::flatten;
use lib::math::polynomial::Polynomial;

fn main(
    shares: [Polynomial<N>; 6],
    expected: pub [Field; 6],
) {
    for k in 0..6 {
        let mut reversed_coeffs: [Field; N] = [0; N];
        for i in 0..N {
            reversed_coeffs[N - 1 - i] = shares[k].coefficients[i];
        }
        let payload = flatten::<N, 1, SHARE_DECRYPTION_BIT_MSG>(
            [].as_vector(),
            [Polynomial::new(reversed_coeffs)],
        );
        let mut acc = 0;
        let len = payload.len();
        for i in 0..len {
            acc = acc * 3641542188856621199 + payload[i]; // fixed odd BN254 scalar
        }
        assert(acc == expected[k], "payload pin");
    }
}
