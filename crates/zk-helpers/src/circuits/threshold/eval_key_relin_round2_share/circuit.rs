// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::registry::Circuit;
use e3_fhe_params::ParameterType;
use e3_polynomial::CrtPolynomial;

#[derive(Debug)]
pub struct EvalKeyRelinRound2ShareCircuit;

impl Circuit for EvalKeyRelinRound2ShareCircuit {
    const NAME: &'static str = "eval-key-relin-round2-share";
    const PREFIX: &'static str = "EVAL_KEY_RELIN_ROUND2_SHARE";
    const SUPPORTED_PARAMETER: ParameterType = ParameterType::THRESHOLD;
    const DKG_INPUT_TYPE: Option<crate::computation::DkgInputType> = None;
}

#[derive(Debug, Clone)]
pub struct EvalKeyRelinRound2ShareCircuitData {
    pub secret_key_share: CrtPolynomial,
    pub ephemeral_u_share: CrtPolynomial,
    pub h0_aggregate: CrtPolynomial,
    pub h1_aggregate: CrtPolynomial,
    pub r0_share: CrtPolynomial,
    pub r1_share: CrtPolynomial,
    pub component_index: u64,
    pub crs_binding_hash: [u8; 32],
    pub additive_share_commitment_hash: [u8; 32],
    pub relin_ephemeral_u_commitment_hash: [u8; 32],
    pub round1_aggregate_digest: [u8; 32],
    pub share_digest: [u8; 32],
    pub ciphertext_level: u64,
    pub key_level: u64,
}
