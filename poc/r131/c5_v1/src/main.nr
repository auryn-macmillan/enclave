// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
//
// r131 C5 probe V1 — secure-8192/small A/B arm: C5 execute() with the H x compute_threshold_pk_commitment
// re-commit block (verify_pk_commitments) DROPPED; the divisibility family (verify_pk_for_basis) + the
// final (pk0_agg, crp) commitment RETAINED verbatim (verify_pk_for_basis body copied from
// circuits/lib/src/core/threshold/pk_aggregation.nr @ 5dcd172b, byte-verified vs addb3d4 in the
// r131 SOURCE-CONE AUDIT, `self` inlined — struct fields qis / pk0 / pk0_agg / crp).
// ABI identical to V0 (3 inputs, 1 output) so the V0-V1 delta attributes cleanly to block (a)
// (r38 I20 pattern, secure-8192 leg per r113).
// SOUNDNESS NOTE: V1 is NOT shippable (pk0 witnesses left unbound to expected_commitments —
// a V1 prover could witness arbitrary pk0 under freely-chosen rows); measurement-only.

use lib::configs::default::H;
use lib::configs::default::threshold::{CRP, L, N, PK_AGGREGATION_BIT_PK, PK_AGGREGATION_CONFIGS};
use lib::math::commitments::compute_pk_aggregation_commitment;
use lib::math::modulo::U64::ModU64;
use lib::math::polynomial::Polynomial;

fn main(
    expected_threshold_pk_commitments: pub [Field; H],
    pk0: [[Polynomial<N>; L]; H],
    pk0_agg: [Polynomial<N>; L],
) -> pub Field {
    // V1: NO verify_pk_commitments(). expected rows public-but-unbound.
    let _ = expected_threshold_pk_commitments;

    // Step 2 (retained): pk0_agg == sum(pk0[h]) mod q_l per CRT basis — verbatim from C5 leaf.
    let qis = PK_AGGREGATION_CONFIGS.qis;
    for basis_idx in 0..L {
        let q_l = qis[basis_idx];
        let mod_q_l = ModU64::new(q_l as u64);
        let half_qi: Field = (q_l - 1) / 2;
        let h_half_qi: Field = H as Field * half_qi;
        let offset: Field = H as Field * q_l;
        for coeff_idx in 0..N {
            let mut sum_shifted: Field = 0;
            for party_idx in 0..H {
                sum_shifted =
                    sum_shifted + pk0[party_idx][basis_idx].coefficients[coeff_idx] + half_qi;
            }
            mod_q_l.assert_zero_mod(
                sum_shifted + offset - pk0_agg[basis_idx].coefficients[coeff_idx] - h_half_qi,
            );
        }
    }

    // Step 3 (retained): commit to (pk0_agg, crp).
    compute_pk_aggregation_commitment::<N, L, PK_AGGREGATION_BIT_PK>(pk0_agg, CRP)
}