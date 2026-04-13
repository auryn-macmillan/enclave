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

#[derive(Message, Derivative, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
#[derivative(Debug)]
pub struct RelinearizationKeyCreated {
    pub e3_id: E3id,
    #[derivative(Debug(format_with = "e3_utils::formatters::hexf"))]
    pub relin_key: ArcBytes,
    pub nodes: OrderedSet<String>,
    pub crs_binding_hash: [u8; 32],
    pub round1_aggregate_digest: [u8; 32],
    pub relin_key_digest: [u8; 32],
}

impl Display for RelinearizationKeyCreated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
