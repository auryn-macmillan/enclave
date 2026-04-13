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
    pub error_bound: Field,
}

impl<let L: u32> Configs<L> {
    pub fn new(qis: [Field; L], error_bound: Field) -> Self {
        Configs { qis, error_bound }
    }
}

pub struct EvalKeyRelinRound2Share<
    let N: u32,
    let L: u32,
    let BIT_SK: u32,
    let BIT_U: u32,
    let BIT_ERROR: u32,
    let BIT_R: u32,
> {
    configs: Configs<L>,
    expected_sk_commitment: Field,
    expected_u_commitment: Field,
    component_index: Field,
    ciphertext_level: Field,
    key_level: Field,
    crs_binding_hash: [u8; 32],
    additive_share_commitment_hash: [u8; 32],
    relin_ephemeral_u_commitment_hash: [u8; 32],
    round1_aggregate_digest: [u8; 32],
    share_digest: [u8; 32],
    h0_agg: Polynomial<N>,
    h1_agg: Polynomial<N>,
    r0: Polynomial<N>,
    r1: Polynomial<N>,
    sk: Polynomial<N>,
    u: Polynomial<N>,
}

impl<
    let N: u32,
    let L: u32,
    let BIT_SK: u32,
    let BIT_U: u32,
    let BIT_ERROR: u32,
    let BIT_R: u32,
> EvalKeyRelinRound2Share<N, L, BIT_SK, BIT_U, BIT_ERROR, BIT_R> {
    pub fn new(
        configs: Configs<L>,
        expected_sk_commitment: Field,
        expected_u_commitment: Field,
        component_index: Field,
        ciphertext_level: Field,
        key_level: Field,
        crs_binding_hash: [u8; 32],
        additive_share_commitment_hash: [u8; 32],
        relin_ephemeral_u_commitment_hash: [u8; 32],
        round1_aggregate_digest: [u8; 32],
        share_digest: [u8; 32],
        h0_agg: Polynomial<N>,
        h1_agg: Polynomial<N>,
        r0: Polynomial<N>,
        r1: Polynomial<N>,
        sk: Polynomial<N>,
        u: Polynomial<N>,
    ) -> Self {
        EvalKeyRelinRound2Share {
            configs,
            expected_sk_commitment,
            expected_u_commitment,
            component_index,
            ciphertext_level,
            key_level,
            crs_binding_hash,
            additive_share_commitment_hash,
            relin_ephemeral_u_commitment_hash,
            round1_aggregate_digest,
            share_digest,
            h0_agg,
            h1_agg,
            r0,
            r1,
            sk,
            u,
        }
    }

    fn verify_sk_commitment(self) {
        assert(
            compute_share_computation_sk_commitment::<N, BIT_SK>(self.sk)
                == self.expected_sk_commitment,
            "sk commitment mismatch",
        );
    }

    fn verify_u_commitment(self) {
        assert(
            compute_share_computation_sk_commitment::<N, BIT_U>(self.u)
                == self.expected_u_commitment,
            "u commitment mismatch",
        );
    }

    fn payload(self) -> Vec<Field> {
        let mut inputs = Vec::new();
        inputs.push(self.expected_sk_commitment);
        inputs.push(self.expected_u_commitment);
        inputs.push(self.component_index);
        inputs.push(self.ciphertext_level);
        inputs.push(self.key_level);
        for i in 0..32 {
            inputs.push(self.crs_binding_hash[i] as Field);
            inputs.push(self.additive_share_commitment_hash[i] as Field);
            inputs.push(self.relin_ephemeral_u_commitment_hash[i] as Field);
            inputs.push(self.round1_aggregate_digest[i] as Field);
            inputs.push(self.share_digest[i] as Field);
        }
        inputs = flatten::<_, _, BIT_R>(inputs, [self.h0_agg]);
        inputs = flatten::<_, _, BIT_R>(inputs, [self.h1_agg]);
        inputs = flatten::<_, _, BIT_R>(inputs, [self.r0]);
        inputs = flatten::<_, _, BIT_R>(inputs, [self.r1]);
        inputs
    }

    fn verify_supported_level_transform_relation(self) {
        assert(self.ciphertext_level == 0, "unsupported ciphertext level for C10");
        assert(self.key_level == 0, "unsupported key level for C10");
    }

    fn verify_bounds(self) {
        let error0 = self.r0.sub(self.sk.mul_negacyclic(self.h0_agg));
        let error1 = self
            .r1
            .sub(self.u.sub(self.sk).mul_negacyclic(self.h1_agg));

        error0.range_check_2bounds::<BIT_ERROR>(
            self.configs.error_bound,
            self.configs.error_bound,
        );
        error1.range_check_2bounds::<BIT_ERROR>(
            self.configs.error_bound,
            self.configs.error_bound,
        );
    }

    fn verify_relin_round2_relations(self) {
        let expected_r0 = self
            .sk
            .mul_negacyclic(self.h0_agg)
            .add(self.r0.sub(self.sk.mul_negacyclic(self.h0_agg)));
        let expected_r1 = self
            .u
            .sub(self.sk)
            .mul_negacyclic(self.h1_agg)
            .add(self.r1.sub(self.u.sub(self.sk).mul_negacyclic(self.h1_agg)));

        assert(
            self.r0.coefficients == expected_r0.coefficients,
            "relin round2 r0 relation mismatch",
        );
        assert(
            self.r1.coefficients == expected_r1.coefficients,
            "relin round2 r1 relation mismatch",
        );
    }

    pub fn execute(self) -> Field {
        self.verify_sk_commitment();
        self.verify_u_commitment();
        self.verify_supported_level_transform_relation();
        self.verify_bounds();
        self.verify_relin_round2_relations();
        compute_threshold_pk_challenge(self.payload())
    }
}
