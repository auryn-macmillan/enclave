// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
//
// r131 C5 probe V2 — secure-8192/small FLOOR arm: C5 execute() with BOTH block (a) (the H re-commit
// sponge loop) AND block (b) (the divisibility family verify_pk_for_basis) DROPPED — only the ABI
// plumbing + the final compute_pk_aggregation_commitment(pk0_agg, CRP) remains (r38 I20 V2 pattern,
// secure-8192 leg). V0-V2 = (a)+(b); V1-V2 = (b) the divisibility family; additivity residual must be 0.
// SOUNDNESS NOTE: V2 is NOT shippable (verifies nothing); measurement-only floor.

use lib::configs::default::H;
use lib::configs::default::threshold::{CRP, L, N, PK_AGGREGATION_BIT_PK};
use lib::math::commitments::compute_pk_aggregation_commitment;
use lib::math::polynomial::Polynomial;

fn main(
    expected_threshold_pk_commitments: pub [Field; H],
    pk0: [[Polynomial<N>; L]; H],
    pk0_agg: [Polynomial<N>; L],
) -> pub Field {
    let _ = expected_threshold_pk_commitments;
    let _ = pk0;

    // Only the final commitment remains (the floor). crp is a circuit-constant input like V0/V1.
    compute_pk_aggregation_commitment::<N, L, PK_AGGREGATION_BIT_PK>(pk0_agg, CRP)
}