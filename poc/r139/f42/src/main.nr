// SPDX-License-Identifier: LGPL-3.0-only
//
// r139 F42 - PER-CELL INSTANTIATION form of the consumer cheap-verify body,
// K=42 cells (the A-shape H=14 x L=3 production cell count). This is the
// in-tree C4 per-(h,l) cell call form the r137 membrane nail says must be
// used (the r137 w42 WRAPPED 42-body blob OOM-d at 30.4 GiB journal
// Consumed peak at the 31 GiB cap). Each verify_cell is an independent
// per-cell call (VERBATIM r137 w6 body: reversed -> flatten BIT=58 ->
// running-acc pin, SAFE sponge DROPPED); 42 explicit calls, no wrap-loop.
// RAN purpose: measure the WALL + peak of the per-cell-call 42 form:
// (a) does it FIT at any unit cap on this 32 GiB box, and (b) what is its
// 4c-pinned compile wall = the runacc-binding WALL term r138 left as a
// DRAFT band in the -94.12% in-leaf wall floor (V1 41.69 s + 0.93 s grid
// row; the binding row's wall was the only remaining unknown).
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
    shares: [Polynomial<N>; 42],
    expected: pub [Field; 42],
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
    assert(verify_cell(shares[24]) == expected[24], "payload pin 24");
    assert(verify_cell(shares[25]) == expected[25], "payload pin 25");
    assert(verify_cell(shares[26]) == expected[26], "payload pin 26");
    assert(verify_cell(shares[27]) == expected[27], "payload pin 27");
    assert(verify_cell(shares[28]) == expected[28], "payload pin 28");
    assert(verify_cell(shares[29]) == expected[29], "payload pin 29");
    assert(verify_cell(shares[30]) == expected[30], "payload pin 30");
    assert(verify_cell(shares[31]) == expected[31], "payload pin 31");
    assert(verify_cell(shares[32]) == expected[32], "payload pin 32");
    assert(verify_cell(shares[33]) == expected[33], "payload pin 33");
    assert(verify_cell(shares[34]) == expected[34], "payload pin 34");
    assert(verify_cell(shares[35]) == expected[35], "payload pin 35");
    assert(verify_cell(shares[36]) == expected[36], "payload pin 36");
    assert(verify_cell(shares[37]) == expected[37], "payload pin 37");
    assert(verify_cell(shares[38]) == expected[38], "payload pin 38");
    assert(verify_cell(shares[39]) == expected[39], "payload pin 39");
    assert(verify_cell(shares[40]) == expected[40], "payload pin 40");
    assert(verify_cell(shares[41]) == expected[41], "payload pin 41");
}