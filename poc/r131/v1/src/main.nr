// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
//
// r131 C4 probe V1 — secure-8192/small A/B arm: C4 execute pipeline with the H*L per-cell
// re-commit block (verify_commitments) DROPPED. compute_aggregated_shares / normalize_aggregated
// are private in lib, so both bodies are copied VERBATIM from
// circuits/lib/src/core/dkg/share_decryption.nr @ 5dcd172b (byte-verified vs addb3d4 in
// r131 SOURCE-CONE AUDIT; the u64-center trick included, no simplification).
// ABI identical to V0 (2 inputs, 1 output) so the V0-V1 gate delta attributes cleanly to the
// dropped re-commit block + its assert (r37 I19 pattern, secure-8192 leg per r37's box-2 child).
// SOUNDNESS NOTE: V1 is NOT shippable (decrypted_shares left unbound to expected_commitments —
// a V1 prover could witness arbitrary polynomials under valid public rows); it exists only to
// measure block (a) at ring-8192. The replacement-scheme savings (V1 minus the retained
// per-party binding cost) are a DESIGN estimate — see design spec — never a measurement.

use lib::configs::default::dkg::{
    L_THRESHOLD, N, QIS_THRESHOLD, SHARE_DECRYPTION_BIT_AGG,
};
use lib::configs::default::H;
use lib::math::commitments::compute_aggregated_shares_commitment;
use lib::math::modulo::U64::ModU64;
use lib::math::polynomial::Polynomial;

/// Verbatim copy of private `compute_aggregated_shares` (share_decryption.nr @ 5dcd172b).
fn compute_aggregated_shares_v0copy<let N: u32, let L: u32, let H: u32>(
    decrypted_shares: [[Polynomial<N>; L]; H],
) -> [Polynomial<N>; L] {
    let mut sum: [Polynomial<N>; L] = [Polynomial::new([0; N]); L];

    for mod_idx in 0..L {
        let mut coeffs = [0 as Field; N];
        for coeff_idx in 0..N {
            let mut total = 0 as Field;
            for party_idx in 0..H {
                total =
                    total + decrypted_shares[party_idx][mod_idx].coefficients[coeff_idx];
            }
            coeffs[coeff_idx] = total;
        }
        sum[mod_idx] = Polynomial::new(coeffs);
    }

    sum
}

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
    // V1: NO verify_commitments(). expected_commitments public-but-unbound.
    let _ = expected_commitments;

    // Step 2 (retained): sum shares coefficient-wise per CRT limb.
    let aggregated = compute_aggregated_shares_v0copy::<N, L_THRESHOLD, H>(decrypted_shares);

    // Step 3 (retained): normalize (reduce mod q, reverse, center).
    let normalized = normalize_aggregated_v0copy::<N, L_THRESHOLD>(aggregated, QIS_THRESHOLD);

    // Step 4 (retained): publish commitment to the aggregate (C6 input).
    compute_aggregated_shares_commitment::<N, L_THRESHOLD, SHARE_DECRYPTION_BIT_AGG>(normalized)
}