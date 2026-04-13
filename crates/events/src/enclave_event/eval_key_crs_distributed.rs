// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{E3id, OrderedSet, Seed};
use actix::Message;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};

#[derive(Message, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct EvalKeyCrsDistributed {
    pub e3_id: E3id,
    pub seed: Seed,
    pub galois_exponents: Vec<u64>,
    pub nodes: OrderedSet<String>,
    pub ciphertext_level: u64,
    pub evaluation_key_level: u64,
    pub relin_key_level: u64,
    pub crs_binding_hash: [u8; 32],
    pub external: bool,
}

impl Display for EvalKeyCrsDistributed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
