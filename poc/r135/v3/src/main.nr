// SPDX-License-Identifier: LGPL-3.0-only
//
// r135 V3 — the 42-cell (H=14 x L=3) CONSUMER cheap-verify BLOCK: the r132 p3
// unit (reversed + packed payload, running-acc pin, SAFE sponge DROPPED =
// 2,749 g/cell RAN r132) restated at the A production shape. Per (honest,
// modulus) slot: reversed coeffs -> flatten BIT=58 payload -> running-field
// accumulator -> assert against the producer-provided commitment pin. This
// is the consumer side of the I18/I19 replacement: the consumer STOPS calling
// compute_share_encryption_commitment_from_message (71,981 g/cell re-commit)
// and pins the producer-attested commitment via the cheap payload stream
// instead. L=3 via configs::secure::threshold::L (the v3 L-import fix, same
// class as leg-1's L=2 defect in v2/v2b sources — recorded there).
use lib::configs::committee::active::H;
use lib::configs::default::dkg::{N, SHARE_DECRYPTION_BIT_MSG};
use lib::configs::secure::threshold::L;
use lib::math::helpers::flatten;
use lib::math::polynomial::Polynomial;

fn main(
    shares: [[Polynomial<N>; L]; H],
    expected: pub [[Field; L]; H],
) {
    for h in 0..H {
        for l in 0..L {
            let mut reversed_coeffs: [Field; N] = [0; N];
            for i in 0..N {
                reversed_coeffs[N - 1 - i] = shares[h][l].coefficients[i];
            }
            let payload = flatten::<N, 1, SHARE_DECRYPTION_BIT_MSG>(
                [].as_vector(),
                [Polynomial::new(reversed_coeffs)],
            );
            let mut acc = 0;
            let len = payload.len();
            for i in 0..len {
                acc = acc * 3641542188856621199 + payload[i]; // fixed odd BN254-field scalar
            }
            assert(acc == expected[h][l], "payload pin");
        }
    }
}