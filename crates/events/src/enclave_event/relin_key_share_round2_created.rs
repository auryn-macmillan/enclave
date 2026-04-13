// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{E3id, SignedProofPayload};
use actix::Message;
use derivative::Derivative;
use e3_utils::utility_types::ArcBytes;
use serde::{Deserialize, Serialize};
use std::{
    fmt::{self, Display},
    sync::Arc,
};

#[derive(Derivative, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[derivative(Debug)]
pub struct RelinKeyShareRound2 {
    pub r0: Vec<ArcBytes>,
    pub r1: Vec<ArcBytes>,
    pub crs_binding_hash: [u8; 32],
    pub additive_share_commitment_hash: [u8; 32],
    pub relin_ephemeral_u_commitment_hash: [u8; 32],
    pub round1_aggregate_digest: [u8; 32],
    pub share_digest: [u8; 32],
}

#[derive(Message, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct RelinKeyShareRound2Created {
    pub e3_id: E3id,
    pub party_id: u64,
    pub node: String,
    pub share: Arc<RelinKeyShareRound2>,
    pub signed_proof: Option<SignedProofPayload>,
    pub external: bool,
}

impl Display for RelinKeyShareRound2Created {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
