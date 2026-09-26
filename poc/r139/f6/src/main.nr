// SPDX-License-Identifier: LGPL-3.0-only
//
// r139 F6 - PER-CELL INSTANTIATION form of the consumer cheap-verify body,
// K=6 cells (r137 w6 twin shape, r132 p3-class body: reversed -> flatten
// BIT=58 -> running-acc pin, SAFE sponge DROPPED). The r137 w42 single-blob
// 42-cell function OOM-d at 30.4 GiB (function-depth class); THIS is the
// per-(h,l) cell CALL form the membrane nail (r137) says the in-tree diff
// must use. Explicit per-cell calls (no generic-indexed subscript loop - a
// K-index loop is the r137 blob shape). RAN purpose: wall + peak of the
// per-cell-call instantiation form at the production BIT/shape, measured at
// K=6 AND K=42 (f42), under the r137 secure-preset-only flip.
use lib::configs::default::dkg::{N, SHARE_DECRYPTION_BIT_MSG};
use lib::math::helpers::flatten;
use lib::math::polynomial::Polynomial;

fn verify_cell(share: Polynomial<N>) -> Field {
    let mut reversed_coeffs: [Field; N] = [0; N];
    for i in 0..N {
        reversed_coeffs[N - 1 - i] = share.coefficients[i];
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
    acc
}

fn main(
    shares: [Polynomial<N>; 6],
    expected: pub [Field; 6],
) {
    assert(verify_cell(shares[0]) == expected[0], "payload pin 0");
    assert(verify_cell(shares[1]) == expected[1], "payload pin 1");
    assert(verify_cell(shares[2]) == expected[2], "payload pin 2");
    assert(verify_cell(shares[3]) == expected[3], "payload pin 3");
    assert(verify_cell(shares[4]) == expected[4], "payload pin 4");
    assert(verify_cell(shares[5]) == expected[5], "payload pin 5");
}