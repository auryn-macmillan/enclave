// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{E3id, OrderedSet};
use actix::Message;
use derivative::Derivative;
use e3_utils::utility_types::ArcBytes;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};

#[derive(Derivative, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[derivative(Debug)]
pub struct GaloisKeyArtifact {
    pub exponent: u64,
    #[derivative(Debug(format_with = "e3_utils::formatters::hexf"))]
    pub data: ArcBytes,
    pub galois_key_digest: [u8; 32],
}

#[derive(Message, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct EvaluationKeyCreated {
    pub e3_id: E3id,
    pub galois_keys: Vec<GaloisKeyArtifact>,
    pub evaluation_key: ArcBytes,
    pub nodes: OrderedSet<String>,
    pub crs_binding_hash: [u8; 32],
    pub evaluation_key_digest: [u8; 32],
}

impl Display for EvaluationKeyCreated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
