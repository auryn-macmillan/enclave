// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{
    E3id, EvalKeyGaloisShareProofRequest, EvalKeyRelinRound1ShareProofRequest,
    EvalKeyRelinRound2ShareProofRequest,
};
use actix::Message;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EvalKeyShareProofPendingKind {
    Galois,
    RelinRound1,
    RelinRound2,
}

#[derive(Message, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct EvalKeyShareProofPending {
    pub e3_id: E3id,
    pub party_id: u64,
    pub kind: EvalKeyShareProofPendingKind,
    pub exponent: Option<u64>,
    pub galois_request: Option<EvalKeyGaloisShareProofRequest>,
    pub relin_round1_request: Option<EvalKeyRelinRound1ShareProofRequest>,
    pub relin_round2_request: Option<EvalKeyRelinRound2ShareProofRequest>,
}

impl Display for EvalKeyShareProofPending {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
