// SPDX-License-Identifier: LGPL-3.0-only
//
// r132 P0 (BASE/SPECS): production per-cell body as-is, mirroring
// ShareDecryption::verify_commitments (share_decryption.nr @ 5dcd172b/68b5c723),
// single (party,moduli) cell. If NO crossover, renormalized at P0/P1 zips
// against the r131 V0-V1 delta (V0 3,571,446 - V1 1,412,585 = 2,158,861).
use lib::configs::default::dkg::{N, SHARE_DECRYPTION_BIT_MSG};
use lib::math::commitments::compute_share_encryption_commitment_from_message;
use lib::math::polynomial::Polynomial;

fn main(
    share: Polynomial<N>,
    expected_commitment: pub Field,
) {
    let mut reversed_coeffs: [Field; N] = [0; N];
    for i in 0..N {
        reversed_coeffs[N - 1 - i] = share.coefficients[i];
    }
    assert(
        compute_share_encryption_commitment_from_message::<N, SHARE_DECRYPTION_BIT_MSG>(
            Polynomial::new(reversed_coeffs),
        ) == expected_commitment,
        "Commitment mismatch",
    );
}