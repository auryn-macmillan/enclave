// SPDX-License-Identifier: LGPL-3.0-only
//
// r141 e_range — option (a) SIZING, LEG 2: base acc-pin (r137 w-class:
// reversed -> flatten ::<N,1,58> -> running-acc pin) + per-coefficient
// range-check family at the CONSUMER cell, mirroring the producer's
// `Polynomial::new([c]).range_check_standard::<BIT_SHARE>(q)`
// (share_computation.nr check_range_bounds, L245-260), parameter-for-
// parameter: the preset's SHARE_COMPUTATION_BIT_SHARE against the preset
// DKG q[mod_idx]. K=6, twin of the r137 w6 base point (16,409 g).
use lib::configs::default::dkg::{
    N, SHARE_DECRYPTION_BIT_MSG, SHARE_COMPUTATION_BIT_SHARE,
};
use lib::math::helpers::flatten;
use lib::math::polynomial::Polynomial;

fn main(
    shares: [Polynomial<N>; 6],
    q: pub [Field; 3],
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
            acc = acc * 3641542188856621199 + payload[i];
        }
        assert(acc == expected[k], "payload pin");
        // per-coefficient range pin, producer family (consumer cell):
        for j in 0..N {
            Polynomial::new([reversed_coeffs[j]])
                .range_check_standard::<SHARE_COMPUTATION_BIT_SHARE>(q[0]);
        }
    }
}