// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{
    threshold::eval_key_relin_round2_share::EvalKeyRelinRound2ShareCircuitData, CircuitsErrors,
};
use e3_fhe_params::{build_pair_for_preset, BfvPreset};
use e3_polynomial::{CrtPolynomial, Polynomial};
use num_bigint::BigInt;

impl EvalKeyRelinRound2ShareCircuitData {
    pub fn generate_sample(preset: BfvPreset) -> Result<Self, CircuitsErrors> {
        let (threshold_params, _) = build_pair_for_preset(preset).map_err(|e| {
            CircuitsErrors::Sample(format!("Failed to build pair for preset: {e:?}"))
        })?;
        let degree = threshold_params.degree();
        let num_moduli = threshold_params.moduli().len();

        let make_poly = |constant: i64| {
            let mut coeffs = vec![BigInt::from(0u8); degree];
            coeffs[degree - 1] = BigInt::from(constant);
            Polynomial::new(coeffs)
        };

        let make_crt = |constant: i64| {
            CrtPolynomial::new((0..num_moduli).map(|_| make_poly(constant)).collect())
        };

        Ok(Self {
            secret_key_share: make_crt(1),
            ephemeral_u_share: make_crt(1),
            h0_aggregate: make_crt(0),
            h1_aggregate: make_crt(0),
            r0_share: make_crt(0),
            r1_share: make_crt(0),
            component_index: 0,
            crs_binding_hash: [0u8; 32],
            additive_share_commitment_hash: [0u8; 32],
            relin_ephemeral_u_commitment_hash: [0u8; 32],
            round1_aggregate_digest: [0u8; 32],
            share_digest: [0u8; 32],
            ciphertext_level: 0,
            key_level: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_sample() {
        let sample =
            EvalKeyRelinRound2ShareCircuitData::generate_sample(BfvPreset::InsecureThreshold512)
                .unwrap();

        assert!(!sample.secret_key_share.limbs.is_empty());
        assert!(!sample.r0_share.limbs.is_empty());
        assert_eq!(sample.component_index, 0);
    }
}
