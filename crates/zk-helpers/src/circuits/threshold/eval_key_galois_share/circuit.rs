// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::registry::Circuit;
use e3_fhe_params::ParameterType;
use e3_polynomial::CrtPolynomial;

#[derive(Debug)]
pub struct EvalKeyGaloisShareCircuit;

impl Circuit for EvalKeyGaloisShareCircuit {
    const NAME: &'static str = "eval-key-galois-share";
    const PREFIX: &'static str = "EVAL_KEY_GALOIS_SHARE";
    const SUPPORTED_PARAMETER: ParameterType = ParameterType::THRESHOLD;
    const DKG_INPUT_TYPE: Option<crate::computation::DkgInputType> = None;
}

#[derive(Debug, Clone)]
pub struct EvalKeyGaloisShareCircuitData {
    pub secret_key_share: CrtPolynomial,
    pub substituted_secret_share: CrtPolynomial,
    pub transformed_secret_share: CrtPolynomial,
    pub c1_share: CrtPolynomial,
    pub error_share: CrtPolynomial,
    pub component_index: u64,
    pub garner_coefficient_decimal: String,
    pub c0_share: CrtPolynomial,
    pub crs_binding_hash: [u8; 32],
    pub additive_share_commitment_hash: [u8; 32],
    pub share_digest: [u8; 32],
    pub exponent: u64,
    pub ciphertext_level: u64,
    pub evaluation_key_level: u64,
}
