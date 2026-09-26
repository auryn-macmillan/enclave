// SPDX-License-Identifier: LGPL-3.0-only
//
// r135 V3S — consumer cheap-verify block (r132 p3-class) at REDUCED H=3 shape
// (H=3 committee, L=3 -> 9 cells): memory-slope probe after the 42-cell v3
// OOM (28 GiB unit cap, peak 28 GiB, 7 min). H comes from the minimum
// committee (N=3/T=1/H=3 present in the tree's minimum set) — leg flips
// DKG preset only (secure), keeps committee::minimum. Same per-cell body as
// v3 (reversed -> flatten BIT=58 -> running-acc pin). If 9 cells fits with
// peak ~ 28 GiB * 9/42 ~= 6 GiB the memory demand is linear-in-cell-count
// (backend flatten-materialization class); if it still OOMs the v3 body is
// unrunnable at ANY realistic committee scale and the consumer-cheap-verify
// route is box-dead (DRAFT only) — either way a load-bearing design datum.
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