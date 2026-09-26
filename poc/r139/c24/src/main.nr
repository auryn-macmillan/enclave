// SPDX-License-Identifier: LGPL-3.0-only
//
// r139 C24 - PER-CELL INSTANTIATION form of the consumer cheap-verify body,
// K=24 explicit verify_cell calls (membrane middle between c12 RAN-GREEN
// 20.0 s and f42 OOM-kill; same verbatim per-cell body: reversed -> flatten
// BIT=58 -> running-acc pin, SAFE sponge DROPPED).
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
    shares: [Polynomial<N>; 24],
    expected: pub [Field; 24],
) {
    assert(verify_cell(shares[0]) == expected[0], "payload pin 0");
    assert(verify_cell(shares[1]) == expected[1], "payload pin 1");
    assert(verify_cell(shares[2]) == expected[2], "payload pin 2");
    assert(verify_cell(shares[3]) == expected[3], "payload pin 3");
    assert(verify_cell(shares[4]) == expected[4], "payload pin 4");
    assert(verify_cell(shares[5]) == expected[5], "payload pin 5");
    assert(verify_cell(shares[6]) == expected[6], "payload pin 6");
    assert(verify_cell(shares[7]) == expected[7], "payload pin 7");
    assert(verify_cell(shares[8]) == expected[8], "payload pin 8");
    assert(verify_cell(shares[9]) == expected[9], "payload pin 9");
    assert(verify_cell(shares[10]) == expected[10], "payload pin 10");
    assert(verify_cell(shares[11]) == expected[11], "payload pin 11");
    assert(verify_cell(shares[12]) == expected[12], "payload pin 12");
    assert(verify_cell(shares[13]) == expected[13], "payload pin 13");
    assert(verify_cell(shares[14]) == expected[14], "payload pin 14");
    assert(verify_cell(shares[15]) == expected[15], "payload pin 15");
    assert(verify_cell(shares[16]) == expected[16], "payload pin 16");
    assert(verify_cell(shares[17]) == expected[17], "payload pin 17");
    assert(verify_cell(shares[18]) == expected[18], "payload pin 18");
    assert(verify_cell(shares[19]) == expected[19], "payload pin 19");
    assert(verify_cell(shares[20]) == expected[20], "payload pin 20");
    assert(verify_cell(shares[21]) == expected[21], "payload pin 21");
    assert(verify_cell(shares[22]) == expected[22], "payload pin 22");
    assert(verify_cell(shares[23]) == expected[23], "payload pin 23");
}