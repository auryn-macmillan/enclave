// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::math::commitments::{
    compute_share_computation_sk_commitment, compute_threshold_pk_challenge,
};
use crate::math::helpers::flatten;
use crate::math::polynomial::Polynomial;

pub struct Configs<let L: u32> {
    pub qis: [Field; L],
}

impl<let L: u32> Configs<L> {
    pub fn new(qis: [Field; L]) -> Self {
        Configs { qis }
    }
}

pub struct EvalKeyGaloisShare<let N: u32, let L: u32, let BIT_SK: u32, let BIT_TRANSFORMED_SK: u32, let BIT_C0: u32> {
    configs: Configs<L>,
    expected_sk_commitment: Field,
    component_index: Field,
    exponent: Field,
    ciphertext_level: Field,
    evaluation_key_level: Field,
    crs_binding_hash: [u8; 32],
    additive_share_commitment_hash: [u8; 32],
    share_digest: [u8; 32],
    garner_coefficient: Field,
    substituted_sk: Polynomial<N>,
    transformed_sk: Polynomial<N>,
    c1: Polynomial<N>,
    c0: Polynomial<N>,
    sk: Polynomial<N>,
    error: Polynomial<N>,
}

impl<let N: u32, let L: u32, let BIT_SK: u32, let BIT_TRANSFORMED_SK: u32, let BIT_C0: u32> EvalKeyGaloisShare<N, L, BIT_SK, BIT_TRANSFORMED_SK, BIT_C0> {
    pub fn new(
        configs: Configs<L>,
        expected_sk_commitment: Field,
        component_index: Field,
        exponent: Field,
        ciphertext_level: Field,
        evaluation_key_level: Field,
        crs_binding_hash: [u8; 32],
        additive_share_commitment_hash: [u8; 32],
        share_digest: [u8; 32],
        garner_coefficient: Field,
        substituted_sk: Polynomial<N>,
        transformed_sk: Polynomial<N>,
        c1: Polynomial<N>,
        c0: Polynomial<N>,
        sk: Polynomial<N>,
        error: Polynomial<N>,
    ) -> Self {
        EvalKeyGaloisShare {
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
        }
    }

    fn verify_sk_commitment(self) {
        assert(
            compute_share_computation_sk_commitment::<N, BIT_SK>(self.sk)
                == self.expected_sk_commitment,
            "sk commitment mismatch",
        );
    }

    fn payload(self) -> Vec<Field> {
        let mut inputs = Vec::new();
        inputs.push(self.expected_sk_commitment);
        inputs.push(self.component_index);
        inputs.push(self.exponent);
        inputs.push(self.ciphertext_level);
        inputs.push(self.evaluation_key_level);
        for i in 0..32 {
            inputs.push(self.crs_binding_hash[i] as Field);
            inputs.push(self.additive_share_commitment_hash[i] as Field);
            inputs.push(self.share_digest[i] as Field);
        }
        inputs.push(self.garner_coefficient);
        inputs = flatten::<_, _, BIT_TRANSFORMED_SK>(inputs, [self.substituted_sk]);
        inputs = flatten::<_, _, BIT_TRANSFORMED_SK>(inputs, [self.transformed_sk]);
        inputs = flatten::<_, _, BIT_C0>(inputs, [self.c1]);
        inputs = flatten::<_, _, BIT_C0>(inputs, [self.c0]);
        inputs
    }

    fn verify_substitution_relation(self) {
        assert(
            self.sk.substitute_x_pow(self.exponent as u32).coefficients
                == self.substituted_sk.coefficients,
            "substituted secret share mismatch",
        );
    }

    fn verify_supported_level_transform_relation(self) {
        assert(self.ciphertext_level == 0, "unsupported ciphertext level for C8");
        assert(self.evaluation_key_level == 0, "unsupported eval-key level for C8");

        assert(
            self.transformed_sk.coefficients == self.substituted_sk.coefficients,
            "transformed secret share mismatch under supported level regime",
        );
    }

    fn verify_rlwe_c0_relation(self) {
        let lhs = self.c0;
        let rhs = self
            .error
            .sub(self.c1.mul_negacyclic(self.sk))
            .add(self.transformed_sk.mul_scalar(self.garner_coefficient));

        assert(
            lhs.coefficients == rhs.coefficients,
            "galois c0 relation mismatch",
        );
    }

    pub fn execute(self) -> Field {
        self.verify_sk_commitment();
        self.verify_substitution_relation();
        self.verify_supported_level_transform_relation();
        self.verify_rlwe_c0_relation();
        compute_threshold_pk_challenge(self.payload())
    }
}
