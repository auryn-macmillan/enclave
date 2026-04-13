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
use std::str::FromStr;

use super::circuit::{EvalKeyGaloisShareCircuit, EvalKeyGaloisShareCircuitData};

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
    pub transformed_sk_bit: u32,
    pub c0_bit: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bounds {
    pub coeff_bounds: Vec<BigUint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inputs {
    pub expected_sk_commitment: String,
    pub secret_key_share: CrtPolynomial,
    pub substituted_secret_share: CrtPolynomial,
    pub transformed_secret_share: CrtPolynomial,
    pub c1_share: CrtPolynomial,
    pub error_share: CrtPolynomial,
    pub component_index: u64,
    pub garner_coefficient: String,
    pub c0_share: CrtPolynomial,
    pub crs_binding_hash: [FieldByte; 32],
    pub additive_share_commitment_hash: [FieldByte; 32],
    pub share_digest: [FieldByte; 32],
    pub exponent: u64,
    pub ciphertext_level: u64,
    pub evaluation_key_level: u64,
}

pub type FieldByte = u8;

#[derive(Debug)]
pub struct EvalKeyGaloisShareComputationOutput {
    pub inputs: Inputs,
}

impl CircuitComputation for EvalKeyGaloisShareCircuit {
    type Preset = BfvPreset;
    type Data = EvalKeyGaloisShareCircuitData;
    type Output = EvalKeyGaloisShareComputationOutput;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, data: &Self::Data) -> Result<Self::Output, Self::Error> {
        Ok(EvalKeyGaloisShareComputationOutput {
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
        Ok(Self {
            sk_bit: coeff_bit,
            transformed_sk_bit: coeff_bit,
            c0_bit: coeff_bit,
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
        Ok(Self { coeff_bounds })
    }
}

impl Computation for Inputs {
    type Preset = BfvPreset;
    type Data = EvalKeyGaloisShareCircuitData;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, data: &Self::Data) -> Result<Self, Self::Error> {
        let bounds = Bounds::compute(preset, &())?;
        let bits = Bits::compute(preset, &bounds)?;
        let idx = usize::try_from(data.component_index).map_err(|e| {
            CircuitsErrors::Other(format!("invalid component index conversion: {e}"))
        })?;
        if idx >= data.secret_key_share.limbs.len() {
            return Err(CircuitsErrors::Other(format!(
                "component index {} out of range for secret_key_share with {} limbs",
                data.component_index,
                data.secret_key_share.limbs.len()
            )));
        }
        if idx >= data.substituted_secret_share.limbs.len() {
            return Err(CircuitsErrors::Other(format!(
                "component index {} out of range for substituted_secret_share with {} limbs",
                data.component_index,
                data.substituted_secret_share.limbs.len()
            )));
        }
        if idx >= data.transformed_secret_share.limbs.len() {
            return Err(CircuitsErrors::Other(format!(
                "component index {} out of range for transformed_secret_share with {} limbs",
                data.component_index,
                data.transformed_secret_share.limbs.len()
            )));
        }
        if idx >= data.c1_share.limbs.len() {
            return Err(CircuitsErrors::Other(format!(
                "component index {} out of range for c1_share with {} limbs",
                data.component_index,
                data.c1_share.limbs.len()
            )));
        }
        if idx >= data.c0_share.limbs.len() {
            return Err(CircuitsErrors::Other(format!(
                "component index {} out of range for c0_share with {} limbs",
                data.component_index,
                data.c0_share.limbs.len()
            )));
        }
        if idx >= data.error_share.limbs.len() {
            return Err(CircuitsErrors::Other(format!(
                "component index {} out of range for error_share with {} limbs",
                data.component_index,
                data.error_share.limbs.len()
            )));
        }
        let expected_sk_commitment =
            compute_share_computation_sk_commitment(data.secret_key_share.limb(idx), bits.sk_bit)
                .to_string();

        Ok(Self {
            expected_sk_commitment,
            secret_key_share: data.secret_key_share.clone(),
            substituted_secret_share: data.substituted_secret_share.clone(),
            transformed_secret_share: data.transformed_secret_share.clone(),
            c1_share: data.c1_share.clone(),
            error_share: data.error_share.clone(),
            component_index: data.component_index,
            garner_coefficient: BigUint::from_str(&data.garner_coefficient_decimal)
                .map_err(|e| CircuitsErrors::Other(format!("invalid garner coefficient: {e}")))?
                .to_string(),
            c0_share: data.c0_share.clone(),
            crs_binding_hash: data.crs_binding_hash,
            additive_share_commitment_hash: data.additive_share_commitment_hash,
            share_digest: data.share_digest,
            exponent: data.exponent,
            ciphertext_level: data.ciphertext_level,
            evaluation_key_level: data.evaluation_key_level,
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
            self.substituted_secret_share.limbs.len(),
            self.transformed_secret_share.limbs.len(),
            self.c1_share.limbs.len(),
            self.c0_share.limbs.len(),
            self.error_share.limbs.len(),
        ]
        .into_iter()
        .min()
        .unwrap_or(0);
        if idx >= limb_count {
            return Err(serde::ser::Error::custom(format!(
                "component index {} out of range for C8 inputs with minimum limb count {}",
                self.component_index, limb_count
            )));
        }
        Ok(serde_json::json!({
            "expected_sk_commitment": self.expected_sk_commitment,
            "component_index": self.component_index,
            "exponent": self.exponent,
            "ciphertext_level": self.ciphertext_level,
            "evaluation_key_level": self.evaluation_key_level,
            "crs_binding_hash": self.crs_binding_hash,
            "additive_share_commitment_hash": self.additive_share_commitment_hash,
            "share_digest": self.share_digest,
            "garner_coefficient": self.garner_coefficient,
            "substituted_sk": limb_json(&self.substituted_secret_share, idx),
            "transformed_sk": limb_json(&self.transformed_secret_share, idx),
            "c1": limb_json(&self.c1_share, idx),
            "c0": limb_json(&self.c0_share, idx),
            "sk": limb_json(&self.secret_key_share, idx),
            "error": limb_json(&self.error_share, idx),
        }))
    }
}
