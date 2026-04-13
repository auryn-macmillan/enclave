// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use lib::configs::default::threshold::{
    EVAL_KEY_RELIN_ROUND1_SHARE_BIT_ERROR, EVAL_KEY_RELIN_ROUND1_SHARE_BIT_H,
    EVAL_KEY_RELIN_ROUND1_SHARE_BIT_SK, EVAL_KEY_RELIN_ROUND1_SHARE_BIT_U, L, N, QIS,
    EVAL_KEY_RELIN_ROUND1_SHARE_ERROR_BOUND, EVAL_KEY_RELIN_ROUND1_SHARE_EPHEMERAL_U_BOUND,
};
use lib::core::threshold::eval_key_relin_round1_share::{Configs, EvalKeyRelinRound1Share};
use lib::math::polynomial::Polynomial;

fn main(
    expected_sk_commitment: pub Field,
    expected_u_commitment: pub Field,
    component_index: pub Field,
    ciphertext_level: pub Field,
    key_level: pub Field,
    crs_binding_hash: pub [u8; 32],
    additive_share_commitment_hash: pub [u8; 32],
    relin_ephemeral_u_commitment_hash: pub [u8; 32],
    share_digest: pub [u8; 32],
    garner_coefficient: pub Field,
    a: Polynomial<N>,
    h0: Polynomial<N>,
    h1: Polynomial<N>,
    sk: Polynomial<N>,
    u: Polynomial<N>,
) -> pub Field {
    let configs: Configs<L> = Configs::new(
        QIS,
        EVAL_KEY_RELIN_ROUND1_SHARE_ERROR_BOUND,
        EVAL_KEY_RELIN_ROUND1_SHARE_EPHEMERAL_U_BOUND,
    );
    let circuit: EvalKeyRelinRound1Share<
        N,
        L,
        EVAL_KEY_RELIN_ROUND1_SHARE_BIT_SK,
        EVAL_KEY_RELIN_ROUND1_SHARE_BIT_U,
        EVAL_KEY_RELIN_ROUND1_SHARE_BIT_ERROR,
        EVAL_KEY_RELIN_ROUND1_SHARE_BIT_H,
    > = EvalKeyRelinRound1Share::new(
        configs,
        expected_sk_commitment,
        expected_u_commitment,
        component_index,
        ciphertext_level,
        key_level,
        crs_binding_hash,
        additive_share_commitment_hash,
        relin_ephemeral_u_commitment_hash,
        share_digest,
        garner_coefficient,
        a,
        h0,
        h1,
        sk,
        u,
    );
    circuit.execute()
}
