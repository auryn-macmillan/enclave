// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use serde::{Deserialize, Serialize};

/// @todo this must be integrated inside Ciphernodes & Smart Contract
/// instead of being a separate type in here. The pvss crate should import this and
/// the default values that must be used and shared among the whole enclave repository.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CiphernodesCommitteeSize {
    /// Small committee size (fast local/testing).
    Small,
    /// Medium committee size (default).
    Medium,
    /// Large committee size (higher assurance).
    Large,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiphernodesCommittee {
    /// Total number of parties (N_PARTIES).
    pub n: usize,
    /// Number of honest parties (H).
    pub h: usize,
    /// Threshold value (T).
    pub threshold: usize,
}

impl CiphernodesCommitteeSize {
    /// Derive the committee size variant from the total number of parties.
    ///
    /// Returns `None` if `n` does not match any known committee size.
    pub fn from_n(n: u64) -> Option<Self> {
        match n {
            5 => Some(CiphernodesCommitteeSize::Small),
            20 => Some(CiphernodesCommitteeSize::Medium),
            80 => Some(CiphernodesCommitteeSize::Large),
            _ => None,
        }
    }

    /// Returns `(num_parties, num_honest_parties, threshold)` for this size.
    pub fn values(self) -> CiphernodesCommittee {
        match self {
            CiphernodesCommitteeSize::Small => CiphernodesCommittee {
                n: 5,
                h: 5,
                threshold: 2,
            },
            CiphernodesCommitteeSize::Medium => CiphernodesCommittee {
                n: 20,
                h: 20,
                threshold: 9,
            },
            CiphernodesCommitteeSize::Large => CiphernodesCommittee {
                n: 80,
                h: 80,
                threshold: 39,
            },
        }
    }
}
