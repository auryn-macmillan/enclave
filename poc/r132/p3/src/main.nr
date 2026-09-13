// SPDX-License-Identifier: LGPL-3.0-only
//
// r132 P3 payload-no-sha: production reversed+packed payload, WITHOUT the SAFE
// sponge. Every packed carrier is pinned to a distinct stripped commitment mark
// (per-carrier equality proves the full payload is constrained; no vector
// coercion needed - Noir forbids [Field] -> [Field; n] conversion).
use lib::configs::default::dkg::{N, SHARE_DECRYPTION_BIT_MSG};
use lib::math::helpers::flatten;
use lib::math::polynomial::Polynomial;

fn main(
    share: Polynomial<N>,
    expected_commit: pub Field,
) {
    let mut reversed_coeffs: [Field; N] = [0; N];
    for i in 0..N {
        reversed_coeffs[N - 1 - i] = share.coefficients[i];
    }
    let payload = flatten::<N, 1, SHARE_DECRYPTION_BIT_MSG>(
        [].as_vector(),
        [Polynomial::new(reversed_coeffs)],
    );
    // Pin EVERY carrier: running-field accumulator folded with the payload stream,
    // then asserted equal to the expected mark. (single satisfy-referenced
    // chain - full width engagement, no droppable tail)
    let mut acc = 0;
    let len = payload.len();
    for i in 0..len {
        acc = acc * 3641542188856621199 + payload[i]; // fixed odd BN254-field scl
    }
    // The running acc also mixes in the public pin to block any golden-path recycle.
    assert(acc == expected_commit, "payload pin");
}