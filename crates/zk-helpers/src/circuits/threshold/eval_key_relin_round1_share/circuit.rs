// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::registry::Circuit;
use e3_fhe_params::ParameterType;
use e3_polynomial::CrtPolynomial;

#[derive(Debug)]
pub struct EvalKeyRelinRound1ShareCircuit;

impl Circuit for EvalKeyRelinRound1ShareCircuit {
    const NAME: &'static str = "eval-key-relin-round1-share";
    const PREFIX: &'static str = "EVAL_KEY_RELIN_ROUND1_SHARE";
    const SUPPORTED_PARAMETER: ParameterType = ParameterType::THRESHOLD;
    const DKG_INPUT_TYPE: Option<crate::computation::DkgInputType> = None;
}

#[derive(Debug, Clone)]
pub struct EvalKeyRelinRound1ShareCircuitData {
    pub secret_key_share: CrtPolynomial,
    pub ephemeral_u_share: CrtPolynomial,
    pub a_share: CrtPolynomial,
    pub h0_share: CrtPolynomial,
    pub h1_share: CrtPolynomial,
    pub component_index: u64,
    pub garner_coefficient_decimal: String,
    pub crs_binding_hash: [u8; 32],
    pub additive_share_commitment_hash: [u8; 32],
    pub relin_ephemeral_u_commitment_hash: [u8; 32],
    pub share_digest: [u8; 32],
    pub ciphertext_level: u64,
    pub key_level: u64,
}
