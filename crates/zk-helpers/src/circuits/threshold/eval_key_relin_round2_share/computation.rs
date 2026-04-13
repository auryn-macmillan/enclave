// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::calculate_bit_width;
use crate::circuits::commitments::compute_share_computation_sk_commitment;
use crate::CircuitsErrors;
use crate::{CircuitComputation, Computation};
use e3_fhe_params::{build_pair_for_preset, BfvPreset};
use e3_polynomial::{CrtPolynomial, Polynomial};
use num_bigint::{BigInt, BigUint};
use serde::{Deserialize, Serialize};

use super::circuit::{EvalKeyRelinRound2ShareCircuit, EvalKeyRelinRound2ShareCircuitData};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Configs {
    pub n: usize,
    pub l: usize,
    pub moduli: Vec<u64>,
    pub bits: Bits,
    pub bounds: Bounds,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bits {
    pub sk_bit: u32,
    pub u_bit: u32,
    pub error_bit: u32,
    pub r_bit: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bounds {
    pub coeff_bounds: Vec<BigUint>,
    pub error_bound: BigUint,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inputs {
    pub expected_sk_commitment: String,
    pub expected_u_commitment: String,
    pub secret_key_share: CrtPolynomial,
    pub ephemeral_u_share: CrtPolynomial,
    pub h0_aggregate: CrtPolynomial,
    pub h1_aggregate: CrtPolynomial,
    pub r0_share: CrtPolynomial,
    pub r1_share: CrtPolynomial,
    pub component_index: u64,
    pub crs_binding_hash: [FieldByte; 32],
    pub additive_share_commitment_hash: [FieldByte; 32],
    pub relin_ephemeral_u_commitment_hash: [FieldByte; 32],
    pub round1_aggregate_digest: [FieldByte; 32],
    pub share_digest: [FieldByte; 32],
    pub ciphertext_level: u64,
    pub key_level: u64,
}

pub type FieldByte = u8;

#[derive(Debug)]
pub struct EvalKeyRelinRound2ShareComputationOutput {
    pub inputs: Inputs,
}

impl CircuitComputation for EvalKeyRelinRound2ShareCircuit {
    type Preset = BfvPreset;
    type Data = EvalKeyRelinRound2ShareCircuitData;
    type Output = EvalKeyRelinRound2ShareComputationOutput;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, data: &Self::Data) -> Result<Self::Output, Self::Error> {
        Ok(EvalKeyRelinRound2ShareComputationOutput {
            inputs: Inputs::compute(preset, data)?,
        })
    }
}

impl Computation for Configs {
    type Preset = BfvPreset;
    type Data = ();
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, _: &Self::Data) -> Result<Self, Self::Error> {
        let (threshold_params, _) =
            build_pair_for_preset(preset).map_err(|e| CircuitsErrors::Other(e.to_string()))?;
        let bounds = Bounds::compute(preset, &())?;
        let bits = Bits::compute(preset, &bounds)?;
        Ok(Self {
            n: threshold_params.degree(),
            l: threshold_params.moduli().len(),
            moduli: threshold_params.moduli().to_vec(),
            bits,
            bounds,
        })
    }
}

impl Computation for Bits {
    type Preset = BfvPreset;
    type Data = Bounds;
    type Error = CircuitsErrors;

    fn compute(_: Self::Preset, data: &Self::Data) -> Result<Self, Self::Error> {
        let coeff_bit = data
            .coeff_bounds
            .iter()
            .map(|bound| calculate_bit_width(BigInt::from(bound.clone())))
            .max()
            .unwrap_or(1);
        let error_bit = calculate_bit_width(BigInt::from(data.error_bound.clone()));
        Ok(Self {
            sk_bit: coeff_bit,
            u_bit: coeff_bit,
            error_bit,
            r_bit: coeff_bit,
        })
    }
}

impl Computation for Bounds {
    type Preset = BfvPreset;
    type Data = ();
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, _: &Self::Data) -> Result<Self, Self::Error> {
        let (threshold_params, _) =
            build_pair_for_preset(preset).map_err(|e| CircuitsErrors::Other(e.to_string()))?;
        let coeff_bounds = threshold_params
            .moduli()
            .iter()
            .map(|qi| BigUint::from((qi - 1) / 2))
            .collect();
        Ok(Self {
            coeff_bounds,
            error_bound: BigUint::from((threshold_params.variance() * 2) as u64),
        })
    }
}

impl Computation for Inputs {
    type Preset = BfvPreset;
    type Data = EvalKeyRelinRound2ShareCircuitData;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, data: &Self::Data) -> Result<Self, Self::Error> {
        let bounds = Bounds::compute(preset, &())?;
        let bits = Bits::compute(preset, &bounds)?;
        let idx = usize::try_from(data.component_index).map_err(|e| {
            CircuitsErrors::Other(format!("invalid component index conversion: {e}"))
        })?;

        for (name, poly) in [
            ("secret_key_share", &data.secret_key_share),
            ("ephemeral_u_share", &data.ephemeral_u_share),
            ("h0_aggregate", &data.h0_aggregate),
            ("h1_aggregate", &data.h1_aggregate),
            ("r0_share", &data.r0_share),
            ("r1_share", &data.r1_share),
        ] {
            if idx >= poly.limbs.len() {
                return Err(CircuitsErrors::Other(format!(
                    "component index {} out of range for {} with {} limbs",
                    data.component_index,
                    name,
                    poly.limbs.len()
                )));
            }
        }

        let expected_sk_commitment =
            compute_share_computation_sk_commitment(data.secret_key_share.limb(idx), bits.sk_bit)
                .to_string();
        let expected_u_commitment =
            compute_share_computation_sk_commitment(data.ephemeral_u_share.limb(idx), bits.u_bit)
                .to_string();

        Ok(Self {
            expected_sk_commitment,
            expected_u_commitment,
            secret_key_share: data.secret_key_share.clone(),
            ephemeral_u_share: data.ephemeral_u_share.clone(),
            h0_aggregate: data.h0_aggregate.clone(),
            h1_aggregate: data.h1_aggregate.clone(),
            r0_share: data.r0_share.clone(),
            r1_share: data.r1_share.clone(),
            component_index: data.component_index,
            crs_binding_hash: data.crs_binding_hash,
            additive_share_commitment_hash: data.additive_share_commitment_hash,
            relin_ephemeral_u_commitment_hash: data.relin_ephemeral_u_commitment_hash,
            round1_aggregate_digest: data.round1_aggregate_digest,
            share_digest: data.share_digest,
            ciphertext_level: data.ciphertext_level,
            key_level: data.key_level,
        })
    }

    fn to_json(&self) -> serde_json::Result<serde_json::Value> {
        fn poly_json(poly: &Polynomial) -> serde_json::Value {
            serde_json::json!({
                "coefficients": poly
                    .coefficients()
                    .iter()
                    .map(|c| c.to_string())
                    .collect::<Vec<_>>()
            })
        }

        fn limb_json(crt: &CrtPolynomial, index: usize) -> serde_json::Value {
            poly_json(crt.limb(index))
        }

        let idx = usize::try_from(self.component_index).map_err(|e| {
            serde::ser::Error::custom(format!("invalid component index conversion: {e}"))
        })?;
        let limb_count = [
            self.secret_key_share.limbs.len(),
            self.ephemeral_u_share.limbs.len(),
            self.h0_aggregate.limbs.len(),
            self.h1_aggregate.limbs.len(),
            self.r0_share.limbs.len(),
            self.r1_share.limbs.len(),
        ]
        .into_iter()
        .min()
        .unwrap_or(0);
        if idx >= limb_count {
            return Err(serde::ser::Error::custom(format!(
                "component index {} out of range for C10 inputs with minimum limb count {}",
                self.component_index, limb_count
            )));
        }

        Ok(serde_json::json!({
            "expected_sk_commitment": self.expected_sk_commitment,
            "expected_u_commitment": self.expected_u_commitment,
            "component_index": self.component_index,
            "ciphertext_level": self.ciphertext_level,
            "key_level": self.key_level,
            "crs_binding_hash": self.crs_binding_hash,
            "additive_share_commitment_hash": self.additive_share_commitment_hash,
            "relin_ephemeral_u_commitment_hash": self.relin_ephemeral_u_commitment_hash,
            "round1_aggregate_digest": self.round1_aggregate_digest,
            "share_digest": self.share_digest,
            "h0_agg": limb_json(&self.h0_aggregate, idx),
            "h1_agg": limb_json(&self.h1_aggregate, idx),
            "r0": limb_json(&self.r0_share, idx),
            "r1": limb_json(&self.r1_share, idx),
            "sk": limb_json(&self.secret_key_share, idx),
            "u": limb_json(&self.ephemeral_u_share, idx),
        }))
    }
}
