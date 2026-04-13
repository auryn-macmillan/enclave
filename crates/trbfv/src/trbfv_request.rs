// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{
    calculate_decryption_key::{CalculateDecryptionKeyRequest, CalculateDecryptionKeyResponse},
    calculate_decryption_share::{
        CalculateDecryptionShareRequest, CalculateDecryptionShareResponse,
    },
    calculate_threshold_decryption::{
        CalculateThresholdDecryptionRequest, CalculateThresholdDecryptionResponse,
    },
    distributed_eval_key::{
        AggregateDistributedEvaluationKeyRequest, AggregateDistributedEvaluationKeyResponse,
        AggregateDistributedGaloisKeyRequest, AggregateDistributedGaloisKeyResponse,
        AggregateDistributedRelinKeyRequest, AggregateDistributedRelinKeyResponse,
        AggregateDistributedRelinRound1Request, AggregateDistributedRelinRound1Response,
        GenerateDistributedGaloisKeyShareRequest, GenerateDistributedGaloisKeyShareResponse,
        GenerateDistributedRelinRound1Request, GenerateDistributedRelinRound1Response,
        GenerateDistributedRelinRound2Request, GenerateDistributedRelinRound2Response,
    },
    gen_esi_sss::{GenEsiSssRequest, GenEsiSssResponse},
    gen_pk_share_and_sk_sss::{GenPkShareAndSkSssRequest, GenPkShareAndSkSssResponse},
};
use core::fmt;
use serde::{Deserialize, Serialize};

// NOTE: All size values use u64 instead of usize to maintain a stable
// protocol that works across different architectures. Convert these
// u64 values to usize when entering the library's internal APIs.

/// Input format for TrBFVRequest
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TrBFVRequest {
    GenEsiSss(GenEsiSssRequest),
    GenPkShareAndSkSss(GenPkShareAndSkSssRequest),
    CalculateDecryptionKey(CalculateDecryptionKeyRequest),
    CalculateDecryptionShare(CalculateDecryptionShareRequest),
    CalculateThresholdDecryption(CalculateThresholdDecryptionRequest),
    GenerateDistributedGaloisKeyShare(GenerateDistributedGaloisKeyShareRequest),
    AggregateDistributedGaloisKey(AggregateDistributedGaloisKeyRequest),
    AggregateDistributedEvaluationKey(AggregateDistributedEvaluationKeyRequest),
    GenerateDistributedRelinRound1(GenerateDistributedRelinRound1Request),
    AggregateDistributedRelinRound1(AggregateDistributedRelinRound1Request),
    GenerateDistributedRelinRound2(GenerateDistributedRelinRound2Request),
    AggregateDistributedRelinKey(AggregateDistributedRelinKeyRequest),
}

/// Result format for TrBFVResponse
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TrBFVResponse {
    GenEsiSss(GenEsiSssResponse),
    GenPkShareAndSkSss(GenPkShareAndSkSssResponse),
    CalculateDecryptionKey(CalculateDecryptionKeyResponse),
    CalculateDecryptionShare(CalculateDecryptionShareResponse),
    CalculateThresholdDecryption(CalculateThresholdDecryptionResponse),
    GenerateDistributedGaloisKeyShare(GenerateDistributedGaloisKeyShareResponse),
    AggregateDistributedGaloisKey(AggregateDistributedGaloisKeyResponse),
    AggregateDistributedEvaluationKey(AggregateDistributedEvaluationKeyResponse),
    GenerateDistributedRelinRound1(GenerateDistributedRelinRound1Response),
    AggregateDistributedRelinRound1(AggregateDistributedRelinRound1Response),
    GenerateDistributedRelinRound2(GenerateDistributedRelinRound2Response),
    AggregateDistributedRelinKey(AggregateDistributedRelinKeyResponse),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TrBFVError {
    GenEsiSss(String),
    GenPkShareAndSkSss(String),
    CalculateDecryptionKey(String),
    CalculateDecryptionShare(String),
    CalculateThresholdDecryption(String),
    GenerateDistributedGaloisKeyShare(String),
    AggregateDistributedGaloisKey(String),
    AggregateDistributedEvaluationKey(String),
    GenerateDistributedRelinRound1(String),
    AggregateDistributedRelinRound1(String),
    GenerateDistributedRelinRound2(String),
    AggregateDistributedRelinKey(String),
}

impl std::error::Error for TrBFVError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            _ => None,
        }
    }
}

impl fmt::Display for TrBFVError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TrBFVError::GenEsiSss(_) => write!(f, "GenEsiSss"),
            TrBFVError::GenPkShareAndSkSss(_) => write!(f, "GenPkShareAndSkSss"),
            TrBFVError::CalculateDecryptionKey(_) => write!(f, "CalculateDecryptionKey"),
            TrBFVError::CalculateDecryptionShare(_) => write!(f, "CalculateDecryptionShare"),
            TrBFVError::CalculateThresholdDecryption(_) => {
                write!(f, "CalculateThresholdDecryption")
            }
            TrBFVError::GenerateDistributedGaloisKeyShare(_) => {
                write!(f, "GenerateDistributedGaloisKeyShare")
            }
            TrBFVError::AggregateDistributedGaloisKey(_) => {
                write!(f, "AggregateDistributedGaloisKey")
            }
            TrBFVError::AggregateDistributedEvaluationKey(_) => {
                write!(f, "AggregateDistributedEvaluationKey")
            }
            TrBFVError::GenerateDistributedRelinRound1(_) => {
                write!(f, "GenerateDistributedRelinRound1")
            }
            TrBFVError::AggregateDistributedRelinRound1(_) => {
                write!(f, "AggregateDistributedRelinRound1")
            }
            TrBFVError::GenerateDistributedRelinRound2(_) => {
                write!(f, "GenerateDistributedRelinRound2")
            }
            TrBFVError::AggregateDistributedRelinKey(_) => {
                write!(f, "AggregateDistributedRelinKey")
            }
        }
    }
}
