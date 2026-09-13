// SPDX-License-Identifier: LGPL-3.0-only
//
// r132 P4 payload-with-sha: production BEHAVIOUR exactly - reversed coeffs ->
// packed payload -> SAFE commitment -> assert against expected (== C4
// verify_commitments body in the single-cell case). This curve is the
// revision anchor in itself (r131 Valencia is 3,571,446 gate).
use lib::configs::default::dkg::{N, SHARE_DECRYPTION_BIT_MSG};
use lib::math::commitments::compute_share_encryption_commitment_from_message;
use lib::math::polynomial::Polynomial;

fn main(
    share: Polynomial<N>,
    expected_commit: pub Field,
) {
    let mut reversed_coeffs: [Field; N] = [0; N];
    for i in 0..N {
        reversed_coeffs[N - 1 - i] = share.coefficients[i];
    }
    let out = compute_share_encryption_commitment_from_message::<N, SHARE_DECRYPTION_BIT_MSG>(
        Polynomial::new(reversed_coeffs),
    );
    assert(out == expected_commit, "pin");
}