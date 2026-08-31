// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Content-addressed data-availability transport used by Interfold applications.
//!
//! Ethereum verifies an Avail/VectorX receipt before it records a reference. Readers still hash
//! the bytes after retrieval. The receipt proves that the committed bytes were published; the
//! reader-side hash prevents a faulty RPC from substituting different bytes.

use alloy_primitives::{keccak256, B256};
use alloy_sol_types::{sol, SolValue};
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Maximum object size accepted by the application transport.
///
/// This matches Avail's current one MiB `submit_data` bound and is deliberately checked before
/// any network request.
pub const MAX_OBJECT_BYTES: usize = 1024 * 1024;

/// Stable coordinates recorded by the Ethereum application after receipt verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DataReference {
    pub content_hash: [u8; 32],
    pub block_number: u32,
    pub leaf_index: u128,
}

/// Avail transaction coordinates needed while the VectorX proof is being produced.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingPublication {
    pub content_hash: [u8; 32],
    pub block_hash: String,
    pub block_number: u32,
    pub extrinsic_index: u32,
}

/// Result returned when the VectorX bridge API has produced an Ethereum proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProofStatus {
    Pending,
    Ready {
        reference: DataReference,
        abi_proof: Vec<u8>,
    },
}

/// Retrieval boundary used by ciphernodes and application servers.
#[async_trait]
pub trait DataAvailabilityReader: Send + Sync {
    async fn retrieve(&self, reference: DataReference) -> Result<Vec<u8>>;
}

/// Publication boundary used by an application availability service.
#[async_trait]
pub trait DataAvailabilityPublisher: Send + Sync {
    async fn publish(&self, bytes: &[u8]) -> Result<PendingPublication>;
    async fn proof(&self, publication: &PendingPublication) -> Result<ProofStatus>;
}

/// Re-hash retrieved bytes against their Ethereum-verified reference.
pub fn verify_retrieved_bytes(reference: DataReference, bytes: Vec<u8>) -> Result<Vec<u8>> {
    validate_size(&bytes)?;
    let actual = keccak256(&bytes);
    if actual.0 != reference.content_hash {
        bail!(
            "data-availability object hash mismatch: expected 0x{}, got {actual}",
            hex::encode(reference.content_hash)
        );
    }
    Ok(bytes)
}

fn validate_size(bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() {
        bail!("data-availability object is empty");
    }
    if bytes.len() > MAX_OBJECT_BYTES {
        bail!(
            "data-availability object is {} bytes; maximum is {MAX_OBJECT_BYTES}",
            bytes.len()
        );
    }
    Ok(())
}

sol! {
    /// Must stay ABI-identical to `IAvailBridge.MerkleProofInput`.
    struct AvailMerkleProofInput {
        bytes32[] dataRootProof;
        bytes32[] leafProof;
        bytes32 rangeHash;
        uint256 dataRootIndex;
        bytes32 blobRoot;
        bytes32 bridgeRoot;
        bytes32 leaf;
        uint256 leafIndex;
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BridgeProofResponse {
    data_root_proof: Vec<B256>,
    leaf_proof: Vec<B256>,
    range_hash: B256,
    data_root_index: u64,
    blob_root: B256,
    bridge_root: B256,
    leaf: B256,
    leaf_index: u64,
}

impl BridgeProofResponse {
    fn into_status(self, expected: [u8; 32]) -> Result<ProofStatus> {
        if self.leaf.0 != expected {
            bail!(
                "bridge proof leaf mismatch: expected 0x{}, got {}",
                hex::encode(expected),
                self.leaf
            );
        }
        let data_root_index = alloy_primitives::U256::from(self.data_root_index);
        let leaf_index = alloy_primitives::U256::from(self.leaf_index);
        let leaf_index_u128: u128 = leaf_index
            .try_into()
            .context("Avail leafIndex does not fit in uint128")?;
        let input = AvailMerkleProofInput {
            dataRootProof: self.data_root_proof,
            leafProof: self.leaf_proof,
            rangeHash: self.range_hash,
            dataRootIndex: data_root_index,
            blobRoot: self.blob_root,
            bridgeRoot: self.bridge_root,
            leaf: self.leaf,
            leafIndex: leaf_index,
        };
        Ok(ProofStatus::Ready {
            reference: DataReference {
                content_hash: expected,
                // The bridge adapter derives and verifies the block number. The bridge API does
                // not include it, so the publisher fills this from its finalized receipt.
                block_number: 0,
                leaf_index: leaf_index_u128,
            },
            abi_proof: input.abi_encode(),
        })
    }
}

/// HTTP client for the official Avail VectorX bridge API.
#[derive(Clone)]
pub struct VectorXBridgeApi {
    client: reqwest::Client,
    base_url: String,
    destination_chain_id: u64,
}

impl VectorXBridgeApi {
    pub fn new(base_url: impl Into<String>, destination_chain_id: u64) -> Result<Self> {
        let base_url = base_url.into().trim_end_matches('/').to_owned();
        if base_url.is_empty() {
            bail!("VectorX bridge API URL is empty");
        }
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .build()
            .context("failed to build VectorX bridge API client")?;
        Ok(Self {
            client,
            base_url,
            destination_chain_id,
        })
    }

    pub async fn proof(&self, publication: &PendingPublication) -> Result<ProofStatus> {
        let url = format!("{}/v1/proof/{}", self.base_url, self.destination_chain_id);
        let response = self
            .client
            .get(url)
            .query(&[
                ("block_hash", publication.block_hash.as_str()),
                ("index", &publication.extrinsic_index.to_string()),
            ])
            .send()
            .await
            .context("VectorX bridge proof request failed")?;

        if response.status() == reqwest::StatusCode::NOT_FOUND
            || response.status() == reqwest::StatusCode::ACCEPTED
        {
            return Ok(ProofStatus::Pending);
        }
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            bail!("VectorX bridge proof request returned {status}: {body}");
        }

        let proof: BridgeProofResponse = response
            .json()
            .await
            .context("VectorX bridge proof response is invalid")?;
        let mut status = proof.into_status(publication.content_hash)?;
        if let ProofStatus::Ready { reference, .. } = &mut status {
            reference.block_number = publication.block_number;
        }
        Ok(status)
    }
}

/// Simple HTTP object reader used by the deterministic local mock.
#[derive(Clone)]
pub struct HttpObjectReader {
    client: reqwest::Client,
    base_url: String,
}

impl HttpObjectReader {
    pub fn new(base_url: impl Into<String>) -> Result<Self> {
        let base_url = base_url.into().trim_end_matches('/').to_owned();
        if base_url.is_empty() {
            bail!("mock data-availability URL is empty");
        }
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30))
            .build()
            .context("failed to build mock data-availability client")?;
        Ok(Self { client, base_url })
    }
}

#[async_trait]
impl DataAvailabilityReader for HttpObjectReader {
    async fn retrieve(&self, reference: DataReference) -> Result<Vec<u8>> {
        let url = format!(
            "{}/objects/0x{}",
            self.base_url,
            hex::encode(reference.content_hash)
        );
        let response = self
            .client
            .get(url)
            .send()
            .await
            .context("mock data-availability request failed")?
            .error_for_status()
            .context("mock data-availability object is unavailable")?;
        let bytes = response
            .bytes()
            .await
            .context("failed to read mock data-availability object")?
            .to_vec();
        verify_retrieved_bytes(reference, bytes)
    }
}

#[cfg(any(feature = "avail-read", feature = "avail-submit"))]
mod avail;

#[cfg(any(feature = "avail-read", feature = "avail-submit"))]
pub use avail::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retrieved_bytes_must_match_the_reference() {
        let bytes = b"available object".to_vec();
        let reference = DataReference {
            content_hash: keccak256(&bytes).0,
            block_number: 7,
            leaf_index: 3,
        };
        assert_eq!(
            verify_retrieved_bytes(reference, bytes.clone()).unwrap(),
            bytes
        );
        assert!(verify_retrieved_bytes(reference, b"substitute".to_vec()).is_err());
    }

    #[test]
    fn official_bridge_response_shape_encodes_for_solidity() {
        let response: BridgeProofResponse = serde_json::from_str(
            r#"{
              "dataRootProof":["0x0395f21560a9ccc1f2aa972601250256fbdb20fd936e1723397ff8d5e4f07b5d"],
              "leafProof":["0x00017cadd87ec12039f98d646afaa33ed843056ad12f5e971cc81be15d00c26f"],
              "rangeHash":"0x21c402a3ccf8df26cb720c6d2fb409f04c809adef7a9a852e463cca83588f4fb",
              "dataRootIndex":48,
              "blobRoot":"0x511030804f9768c9d5c4826cdc7eba25ba0fd8e73ea32467e5fad547397620f8",
              "bridgeRoot":"0xf6c807bc73a637957a61d620bd5e4ef8c7dd234e5fc96dfb6d6041bbe2947782",
              "leaf":"0xe17de7631392427460102691ba8a22adf5fb410548e50d6c636bf1f96840c3c3",
              "leafIndex":0,
              "blockHash":"0x5bc7bd3a4793132007d6d0d9c55dc2ded2fe721a49bd771c1d290e6a3c6ec237"
            }"#,
        )
        .unwrap();
        let expected = response.leaf.0;
        let ProofStatus::Ready {
            reference,
            abi_proof,
        } = response.into_status(expected).unwrap()
        else {
            panic!("a complete bridge proof must be ready");
        };

        let decoded = AvailMerkleProofInput::abi_decode(&abi_proof).unwrap();
        assert_eq!(decoded.leaf.0, expected);
        assert_eq!(decoded.dataRootIndex, alloy_primitives::U256::from(48));
        assert_eq!(reference.content_hash, expected);
        assert_eq!(reference.leaf_index, 0);
    }
}
