// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
//
// r131 C4 probe V2 — secure-8192/small FLOOR arm: C4 execute with BOTH the H*L re-commit block
// (verify_commitments) AND the H-fold aggregation (compute_aggregated_shares) DROPPED. What
// remains: the moduli-reverse-center pass (normalize_aggregated, verbatim copy from
// circuits/lib/src/core/dkg/share_decryption.nr @ 5dcd172b) fixed-pointed on the share witness
// itself, then the final aggregated-shares sponge (compute_aggregated_shares_commitment).
// V0-V2 = (a)+(b); V1-V2 = (b) the H-fold term;
// both deltas must sum EXACTLY to V0-V1 (additivity residual 0, r37/r38 caliber).
// SOUNDNESS NOTE: V2 is NOT shippable (nothing in the circuit is bound to the public rows);
// measurement-only floor.

use lib::configs::default::dkg::{
    L_THRESHOLD, N, QIS_THRESHOLD, SHARE_DECRYPTION_BIT_AGG,
};
use lib::configs::default::H;
use lib::math::commitments::compute_aggregated_shares_commitment;
use lib::math::modulo::U64::ModU64;
use lib::math::polynomial::Polynomial;

/// Verbatim copy of private `normalize_aggregated` (share_decryption.nr @ 5dcd172b).
fn normalize_aggregated_v0copy<let N: u32, let L: u32>(
    aggregated: [Polynomial<N>; L],
    moduli: [Field; L],
) -> [Polynomial<N>; L] {
    let mut normalized: [Polynomial<N>; L] = [Polynomial::new([0; N]); L];

    for mod_idx in 0..L {
        let poly = aggregated[mod_idx];
        let q = moduli[mod_idx];
        let half = (q - 1) / 2;

        let mut coeffs: [Field; N] = [0; N];
        for i in 0..N {
            // Reverse: position i gets the coefficient from N-1-i.
            let c = poly.coefficients[N - 1 - i];
            // c < H*q_l (sum of H shares); quotient < H (small) -- safe for ModU64.
            let reduced = ModU64::new(q as u64).reduce_mod(c);
            // Center: shift to [-(q-1)/2, (q-1)/2].
            let centered = if (reduced as u64) > (half as u64) {
                reduced - q
            } else {
                reduced
            };
            coeffs[i] = centered;
        }
        normalized[mod_idx] = Polynomial::new(coeffs);
    }

    normalized
}

fn main(
    expected_commitments: pub [[Field; L_THRESHOLD]; H],
    decrypted_shares: [[Polynomial<N>; L_THRESHOLD]; H],
) -> pub Field {
    // V2: NO verify_commitments(); NO H-fold aggregation (decrypted_shares used directly).
    let _ = expected_commitments;

    // (b) DROPPED: no H-fold aggregation. normalize_aggregated operates on
    // decrypted_shares[0] (the first honest party's per-limb polys - floor stand-in; V1-V2
    // isolates the H-fold term regardless of this choice).
    let normalized =
        normalize_aggregated_v0copy::<N, L_THRESHOLD>(decrypted_shares[0], QIS_THRESHOLD);

    // Final commitment (retained — the floor).
    compute_aggregated_shares_commitment::<N, L_THRESHOLD, SHARE_DECRYPTION_BIT_AGG>(normalized)
}