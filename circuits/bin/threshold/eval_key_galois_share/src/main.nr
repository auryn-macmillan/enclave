// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use lib::configs::default::threshold::{
    L, N, QIS, EVAL_KEY_GALOIS_SHARE_BIT_C0, EVAL_KEY_GALOIS_SHARE_BIT_SK,
    EVAL_KEY_GALOIS_SHARE_BIT_TRANSFORMED_SK,
};
use lib::core::threshold::eval_key_galois_share::{Configs, EvalKeyGaloisShare};
use lib::math::polynomial::Polynomial;

fn main(
    expected_sk_commitment: pub Field,
    component_index: pub Field,
    exponent: pub Field,
    ciphertext_level: pub Field,
    evaluation_key_level: pub Field,
    crs_binding_hash: pub [u8; 32],
    additive_share_commitment_hash: pub [u8; 32],
    share_digest: pub [u8; 32],
    garner_coefficient: pub Field,
    substituted_sk: Polynomial<N>,
    transformed_sk: Polynomial<N>,
    c1: Polynomial<N>,
    c0: Polynomial<N>,
    sk: Polynomial<N>,
    error: Polynomial<N>,
) -> pub Field {
    let configs: Configs<L> = Configs::new(QIS);
    let circuit: EvalKeyGaloisShare<N, L, EVAL_KEY_GALOIS_SHARE_BIT_SK, EVAL_KEY_GALOIS_SHARE_BIT_TRANSFORMED_SK, EVAL_KEY_GALOIS_SHARE_BIT_C0> = EvalKeyGaloisShare::new(
        configs,
        expected_sk_commitment,
        component_index,
        exponent,
        ciphertext_level,
        evaluation_key_level,
        crs_binding_hash,
        additive_share_commitment_hash,
        share_digest,
        garner_coefficient,
        substituted_sk,
        transformed_sk,
        c1,
        c0,
        sk,
        error,
    );
    circuit.execute()
}
