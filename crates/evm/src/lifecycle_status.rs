// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Finalized on-chain lifecycle reads for startup recovery.

use crate::{contracts::IInterfold, EthProvider};
use alloy::{
    eips::{BlockId, BlockNumberOrTag},
    primitives::{Address, U256},
    providers::Provider,
};
use anyhow::{bail, Context, Result};
use e3_events::{E3Stage, E3id, FailureReason};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalE3Lifecycle {
    pub stage: E3Stage,
    pub failure_reason: Option<FailureReason>,
}

fn decode_stage(value: u8) -> Result<E3Stage> {
    Ok(match value {
        0 => E3Stage::None,
        1 => E3Stage::Requested,
        2 => E3Stage::CommitteeFinalized,
        3 => E3Stage::KeyPublished,
        4 => E3Stage::CiphertextReady,
        5 => E3Stage::Complete,
        6 => E3Stage::Failed,
        _ => bail!("unknown on-chain E3 stage {value}"),
    })
}

fn decode_failure_reason(value: u8) -> Result<FailureReason> {
    Ok(match value {
        1 => FailureReason::CommitteeFormationTimeout,
        2 => FailureReason::InsufficientCommitteeMembers,
        3 => FailureReason::DKGTimeout,
        4 => FailureReason::DKGInvalidShares,
        5 => FailureReason::NoInputsReceived,
        6 => FailureReason::ComputeTimeout,
        7 => FailureReason::ComputeProviderExpired,
        8 => FailureReason::ComputeProviderFailed,
        9 => FailureReason::RequesterCancelled,
        10 => FailureReason::DecryptionTimeout,
        11 => FailureReason::DecryptionInvalidShares,
        12 => FailureReason::VerificationFailed,
        _ => bail!("unknown on-chain E3 failure reason {value}"),
    })
}

/// Read the lifecycle state from Ethereum's finalized block.
///
/// Recovery uses finalized state because removing a persisted request context is irreversible for
/// that local node. A near-head reorganization must not make the node discard live E3 state.
pub async fn fetch_finalized_e3_lifecycle<P>(
    provider: &EthProvider<P>,
    interfold_address: Address,
    e3_id: &E3id,
) -> Result<CanonicalE3Lifecycle>
where
    P: Provider + Clone,
{
    let raw_e3_id: U256 = e3_id
        .clone()
        .try_into()
        .with_context(|| format!("invalid E3 ID {e3_id}"))?;
    let block = BlockId::Number(BlockNumberOrTag::Finalized);
    let contract = IInterfold::new(interfold_address, provider.provider());
    let stage = decode_stage(
        contract
            .getE3Stage(raw_e3_id)
            .block(block)
            .call()
            .await
            .with_context(|| format!("failed to read finalized stage for E3 {e3_id}"))?,
    )?;
    if stage == E3Stage::None {
        bail!("persisted request context references unknown on-chain E3 {e3_id}");
    }

    let failure_reason = if stage == E3Stage::Failed {
        Some(decode_failure_reason(
            contract
                .getFailureReason(raw_e3_id)
                .block(block)
                .call()
                .await
                .with_context(|| {
                    format!("failed to read finalized failure reason for E3 {e3_id}")
                })?,
        )?)
    } else {
        None
    };

    Ok(CanonicalE3Lifecycle {
        stage,
        failure_reason,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_codes_reject_unknown_values() {
        assert_eq!(decode_stage(6).unwrap(), E3Stage::Failed);
        assert_eq!(
            decode_failure_reason(5).unwrap(),
            FailureReason::NoInputsReceived
        );
        assert!(decode_stage(7).is_err());
        assert!(decode_failure_reason(0).is_err());
    }
}
