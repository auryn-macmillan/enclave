// SPDX-License-Identifier: LGPL-3.0-only

//! Persistent publication jobs for CRISP's large encrypted objects.

use crate::{config::Config, server::models::e3_id_to_u256};
use alloy::{
    eips::BlockNumberOrTag,
    primitives::{keccak256, Bytes, B256},
    providers::{Provider, ProviderBuilder},
    sol,
    sol_types::SolValue,
};
use e3_data_availability::{
    AvailPublisher, AvailReader, DataAvailabilityPublisher, DataAvailabilityReader, DataReference,
    PendingPublication, ProofStatus,
};
use e3_evm_helpers::contracts::{E3Stage, InterfoldContractFactory, InterfoldRead, InterfoldWrite};
use evm_helpers::CRISPContract;
use serde::{Deserialize, Serialize};
use sled::{Db, Tree};
use std::{collections::HashSet, sync::Arc, time::Duration};
use tokio::sync::Mutex;
use tracing::warn;

const JOB_POLL_INTERVAL: Duration = Duration::from_secs(30);

sol! {
    struct InputEnvelope {
        bytes noirProof;
        address slotAddress;
        bytes32 encryptedVoteCommitment;
        bytes32 encryptedVoteHash;
        uint40 parentIndexPlusOne;
        bytes availabilityProof;
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum JobKind {
    Input {
        e3_id: String,
        staged_envelope: Vec<u8>,
        #[serde(default = "no_deadline")]
        deadline: u64,
    },
    Output {
        e3_id: String,
        ciphertext_commitment: [u8; 32],
        compute_proof: Vec<u8>,
        #[serde(default = "no_deadline")]
        deadline: u64,
    },
}

const fn no_deadline() -> u64 {
    u64::MAX
}

impl JobKind {
    fn deadline(&self) -> u64 {
        match self {
            Self::Input { deadline, .. } | Self::Output { deadline, .. } => *deadline,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum JobState {
    Created,
    AwaitingProof { publication: PendingPublication },
    Ready { ethereum_payload: Vec<u8> },
    Submitted { transaction_hash: String },
    Failed { message: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct AvailabilityJob {
    id: String,
    content_hash: [u8; 32],
    object: Vec<u8>,
    kind: JobKind,
    state: JobState,
}

#[derive(Clone, Debug, Serialize)]
pub struct AvailabilityJobView {
    pub job_id: String,
    pub status: String,
    pub tx_hash: Option<String>,
    pub encoded_proof: Option<String>,
    pub message: Option<String>,
}

/// Durable work item created when Ethereum accepts an input reference.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AvailableInputReference {
    pub e3_id: String,
    pub content_hash: [u8; 32],
    pub availability_block: u32,
    pub availability_leaf_index: u128,
    pub index: u64,
    pub commitment: [u8; 32],
    pub slot: [u8; 20],
    pub parent_index_plus_one: u64,
}

impl AvailableInputReference {
    fn key(&self) -> String {
        format!("{}:{}", self.e3_id, self.index)
    }

    pub fn data_reference(&self) -> DataReference {
        DataReference {
            content_hash: self.content_hash,
            block_number: self.availability_block,
            leaf_index: self.availability_leaf_index,
        }
    }
}

impl From<&AvailabilityJob> for AvailabilityJobView {
    fn from(job: &AvailabilityJob) -> Self {
        let (status, tx_hash, encoded_proof, message) = match &job.state {
            JobState::Created | JobState::AwaitingProof { .. } => {
                ("pending_availability", None, None, None)
            }
            JobState::Ready { ethereum_payload } => (
                "ready_for_submission",
                None,
                Some(format!("0x{}", hex::encode(ethereum_payload))),
                None,
            ),
            JobState::Submitted { transaction_hash } => (
                "success",
                (transaction_hash != "already-finalized").then(|| transaction_hash.clone()),
                None,
                None,
            ),
            JobState::Failed { message } => ("failed_broadcast", None, None, Some(message.clone())),
        };
        Self {
            job_id: job.id.clone(),
            status: status.to_owned(),
            tx_hash,
            encoded_proof,
            message,
        }
    }
}

enum Backend {
    Mock,
    Avail {
        publisher: Arc<AvailPublisher>,
        reader: Arc<AvailReader>,
    },
}

/// Owns persistent publication state and resumes incomplete jobs after restart.
#[derive(Clone)]
pub struct AvailabilityService {
    jobs: Tree,
    objects: Tree,
    input_retrievals: Tree,
    backend: Arc<Backend>,
    in_progress: Arc<Mutex<HashSet<String>>>,
    chain_id: u64,
    http_rpc_url: String,
    private_key: String,
    interfold_address: String,
    e3_program_address: String,
    proof_lead_seconds: u64,
}

impl AvailabilityService {
    pub fn new(db: &Db, config: &Config) -> anyhow::Result<Self> {
        let mode = config.data_availability_mode();
        let backend = match mode.as_str() {
            "mock" => Backend::Mock,
            "avail" => {
                let rpc_url = config
                    .avail_rpc_url
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("AVAIL_RPC_URL is required"))?;
                Backend::Avail {
                    publisher: Arc::new(AvailPublisher::new(
                        rpc_url,
                        config
                            .avail_app_id
                            .ok_or_else(|| anyhow::anyhow!("AVAIL_APP_ID is required"))?,
                        config
                            .avail_seed
                            .as_deref()
                            .ok_or_else(|| anyhow::anyhow!("AVAIL_SEED is required"))?,
                        config
                            .avail_bridge_api_url
                            .as_deref()
                            .ok_or_else(|| anyhow::anyhow!("AVAIL_BRIDGE_API_URL is required"))?,
                        config.chain_id,
                    )?),
                    reader: Arc::new(AvailReader::new(rpc_url)?),
                }
            }
            other => anyhow::bail!("unsupported DATA_AVAILABILITY_MODE '{other}'"),
        };
        Ok(Self {
            jobs: db.open_tree("data-availability-jobs")?,
            objects: db.open_tree("data-availability-objects")?,
            input_retrievals: db.open_tree("data-availability-input-retrievals")?,
            backend: Arc::new(backend),
            in_progress: Arc::new(Mutex::new(HashSet::new())),
            chain_id: config.chain_id,
            http_rpc_url: config.http_rpc_url.clone(),
            private_key: config.private_key.clone(),
            interfold_address: config.interfold_address.clone(),
            e3_program_address: config.e3_program_address.clone(),
            proof_lead_seconds: config.avail_proof_lead_seconds.unwrap_or(10_800),
        })
    }

    pub async fn stage_input(
        &self,
        e3_id: &str,
        encoded_envelope: Vec<u8>,
    ) -> anyhow::Result<AvailabilityJobView> {
        let envelope = InputEnvelope::abi_decode(&encoded_envelope)?;
        let actual = keccak256(&envelope.availabilityProof);
        anyhow::ensure!(
            actual == envelope.encryptedVoteHash,
            "the staged ciphertext does not match encryptedVoteHash"
        );

        let id = self.job_id(b"input", e3_id, actual, &encoded_envelope);
        if let Some(mut job) = self.load(&id)? {
            if matches!(&job.state, JobState::Ready { .. }) && self.input_is_published(&job).await?
            {
                job.state = JobState::Submitted {
                    transaction_hash: "already-finalized".to_owned(),
                };
                self.save(&job)?;
            }
            return Ok((&job).into());
        }

        // Reject invalid Noir proofs before the service pays an Avail submission fee.
        let contract = CRISPContract::new(
            &self.http_rpc_url,
            &self.private_key,
            &self.e3_program_address,
        )
        .await
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        contract
            .validate_input_proof(
                e3_id_to_u256(e3_id)?,
                envelope.noirProof.clone(),
                envelope.slotAddress,
                envelope.encryptedVoteCommitment,
                envelope.encryptedVoteHash,
                envelope.parentIndexPlusOne.to::<u64>(),
            )
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;

        let deadline = if matches!(&*self.backend, Backend::Avail { .. }) {
            let interfold =
                InterfoldContractFactory::create_read(&self.http_rpc_url, &self.interfold_address)
                    .await
                    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            let e3 = interfold
                .get_e3(e3_id_to_u256(e3_id)?)
                .await
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            let now = self.chain_timestamp().await?;
            let deadline: u64 = e3.inputWindow[1]
                .try_into()
                .map_err(|_| anyhow::anyhow!("input deadline does not fit in u64"))?;
            anyhow::ensure!(
                deadline > now.saturating_add(self.proof_lead_seconds),
                "the input window closes before VectorX can safely prove this publication"
            );
            deadline
        } else {
            no_deadline()
        };

        let job = AvailabilityJob {
            id: id.clone(),
            content_hash: actual.0,
            object: envelope.availabilityProof.to_vec(),
            kind: JobKind::Input {
                e3_id: e3_id.to_owned(),
                staged_envelope: encoded_envelope,
                deadline,
            },
            state: JobState::Created,
        };
        self.save(&job)?;
        if matches!(&*self.backend, Backend::Mock) {
            self.process(&id).await;
            self.process(&id).await;
        }
        Ok((&self.load_required(&id)?).into())
    }

    pub async fn stage_output(
        &self,
        e3_id: &str,
        ciphertext: Vec<u8>,
        ciphertext_commitment: [u8; 32],
        compute_proof: Vec<u8>,
    ) -> anyhow::Result<AvailabilityJobView> {
        let hash = keccak256(&ciphertext);
        let mut request_identity = Vec::with_capacity(32 + compute_proof.len());
        request_identity.extend_from_slice(&ciphertext_commitment);
        request_identity.extend_from_slice(&compute_proof);
        let id = self.job_id(b"output", e3_id, hash, &request_identity);
        if let Some(job) = self.load(&id)? {
            return Ok((&job).into());
        }
        let deadline = if matches!(&*self.backend, Backend::Avail { .. }) {
            let interfold =
                InterfoldContractFactory::create_read(&self.http_rpc_url, &self.interfold_address)
                    .await
                    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            let e3_id_value = e3_id_to_u256(e3_id)?;
            anyhow::ensure!(
                interfold
                    .get_e3_stage(e3_id_value)
                    .await
                    .map_err(|error| anyhow::anyhow!(error.to_string()))?
                    == E3Stage::KeyPublished,
                "the E3 is not accepting an aggregate ciphertext"
            );
            let deadlines = interfold
                .get_deadlines(e3_id_value)
                .await
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            let deadline: u64 = deadlines
                .computeDeadline
                .try_into()
                .map_err(|_| anyhow::anyhow!("compute deadline does not fit in u64"))?;
            let now = self.chain_timestamp().await?;
            anyhow::ensure!(
                deadline > now.saturating_add(self.proof_lead_seconds),
                "the compute deadline arrives before VectorX can safely prove this publication"
            );
            deadline
        } else {
            no_deadline()
        };
        let job = AvailabilityJob {
            id: id.clone(),
            content_hash: hash.0,
            object: ciphertext,
            kind: JobKind::Output {
                e3_id: e3_id.to_owned(),
                ciphertext_commitment,
                compute_proof,
                deadline,
            },
            state: JobState::Created,
        };
        self.save(&job)?;
        if matches!(&*self.backend, Backend::Mock) {
            self.process(&id).await;
            self.process(&id).await;
        }
        Ok((&self.load_required(&id)?).into())
    }

    pub fn view(&self, id: &str) -> anyhow::Result<Option<AvailabilityJobView>> {
        Ok(self.load(id)?.as_ref().map(Into::into))
    }

    pub fn object(&self, hash: &str) -> anyhow::Result<Option<Vec<u8>>> {
        let hash = hash.strip_prefix("0x").unwrap_or(hash);
        let key = hex::decode(hash)?;
        Ok(self.objects.get(key)?.map(|value| value.to_vec()))
    }

    /// Retrieve bytes named by a receipt that the Ethereum contract already accepted.
    pub async fn retrieve(&self, reference: DataReference) -> anyhow::Result<Vec<u8>> {
        if let Some(bytes) = self
            .objects
            .get(reference.content_hash)?
            .map(|value| value.to_vec())
        {
            return e3_data_availability::verify_retrieved_bytes(reference, bytes);
        }

        let bytes = match &*self.backend {
            Backend::Mock => anyhow::bail!(
                "local data-availability object 0x{} is not stored",
                hex::encode(reference.content_hash)
            ),
            Backend::Avail { reader, .. } => reader.retrieve(reference).await?,
        };
        self.objects
            .insert(reference.content_hash, bytes.as_slice())?;
        self.objects.flush()?;
        Ok(bytes)
    }

    pub fn record_input_reference(
        &self,
        reference: &AvailableInputReference,
    ) -> anyhow::Result<()> {
        self.input_retrievals
            .insert(reference.key(), serde_json::to_vec(reference)?)?;
        self.input_retrievals.flush()?;
        Ok(())
    }

    pub fn pending_input_references(&self) -> Vec<AvailableInputReference> {
        self.input_retrievals
            .iter()
            .filter_map(|entry| {
                let (_, value) = entry.ok()?;
                serde_json::from_slice(&value).ok()
            })
            .collect()
    }

    pub fn complete_input_reference(
        &self,
        reference: &AvailableInputReference,
    ) -> anyhow::Result<()> {
        self.input_retrievals.remove(reference.key())?;
        self.input_retrievals.flush()?;
        Ok(())
    }

    pub async fn run(self: Arc<Self>) {
        loop {
            let ids = self.pending_ids();
            for id in ids {
                let service = Arc::clone(&self);
                tokio::spawn(async move {
                    service.process(&id).await;
                });
            }
            tokio::time::sleep(JOB_POLL_INTERVAL).await;
        }
    }

    async fn process(&self, id: &str) {
        {
            let mut active = self.in_progress.lock().await;
            if !active.insert(id.to_owned()) {
                return;
            }
        }
        if let Err(error) = self.process_inner(id).await {
            warn!(job_id = id, %error, "Data-availability job will retry");
        }
        self.in_progress.lock().await.remove(id);
    }

    async fn process_inner(&self, id: &str) -> anyhow::Result<()> {
        let mut job = self.load_required(id)?;
        let terminal = matches!(
            job.state,
            JobState::Submitted { .. } | JobState::Failed { .. }
        );
        if !terminal && self.ethereum_publication_exists(&job).await? {
            job.state = JobState::Submitted {
                transaction_hash: "already-finalized".to_owned(),
            };
            self.save(&job)?;
            return Ok(());
        }
        if matches!(&*self.backend, Backend::Avail { .. })
            && !terminal
            && self.chain_timestamp().await? >= job.kind.deadline()
        {
            job.state = JobState::Failed {
                message:
                    "the Ethereum publication deadline passed before the availability job completed"
                        .to_owned(),
            };
            self.save(&job)?;
            return Ok(());
        }
        match &job.state {
            JobState::Created => {
                match &*self.backend {
                    Backend::Mock => {
                        self.objects
                            .insert(job.content_hash, job.object.as_slice())?;
                        job.state = JobState::Ready {
                            ethereum_payload: self.ethereum_payload(&job, job.object.clone())?,
                        };
                    }
                    Backend::Avail { publisher, .. } => {
                        let publication = publisher.publish(&job.object).await?;
                        anyhow::ensure!(
                            publication.content_hash == job.content_hash,
                            "Avail returned a different content hash"
                        );
                        job.state = JobState::AwaitingProof { publication };
                    }
                }
                self.save(&job)?;
            }
            JobState::AwaitingProof { publication } => {
                let Backend::Avail { publisher, .. } = &*self.backend else {
                    anyhow::bail!("mock job cannot await a VectorX proof");
                };
                if let ProofStatus::Ready { abi_proof, .. } = publisher.proof(publication).await? {
                    job.state = JobState::Ready {
                        ethereum_payload: self.ethereum_payload(&job, abi_proof)?,
                    };
                    self.save(&job)?;
                }
            }
            JobState::Ready { ethereum_payload } => {
                if matches!(&job.kind, JobKind::Input { .. })
                    && self.input_is_published(&job).await?
                {
                    job.state = JobState::Submitted {
                        transaction_hash: "already-finalized".to_owned(),
                    };
                    self.save(&job)?;
                    return Ok(());
                }
                match &job.kind {
                    JobKind::Input { .. } if self.chain_id == 1 => {
                        // A mainnet voter submits this payload from their wallet.
                    }
                    JobKind::Input { e3_id, .. } => {
                        let contract = CRISPContract::new(
                            &self.http_rpc_url,
                            &self.private_key,
                            &self.e3_program_address,
                        )
                        .await
                        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                        let e3_id = e3_id_to_u256(e3_id)?;
                        contract
                            .simulate_publish_input(e3_id, Bytes::copy_from_slice(ethereum_payload))
                            .await
                            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                        let receipt = contract
                            .publish_input(e3_id, Bytes::copy_from_slice(ethereum_payload))
                            .await
                            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                        job.state = JobState::Submitted {
                            transaction_hash: receipt.transaction_hash.to_string(),
                        };
                        self.save(&job)?;
                    }
                    JobKind::Output {
                        e3_id,
                        ciphertext_commitment,
                        compute_proof,
                        ..
                    } => {
                        let contract = InterfoldContractFactory::create_write(
                            &self.http_rpc_url,
                            &self.interfold_address,
                            &self.private_key,
                        )
                        .await
                        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                        let e3_id = e3_id_to_u256(e3_id)?;
                        let stage = contract
                            .get_e3_stage(e3_id)
                            .await
                            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                        match stage {
                            E3Stage::KeyPublished => {}
                            E3Stage::CiphertextReady | E3Stage::Complete => {
                                job.state = JobState::Submitted {
                                    transaction_hash: "already-finalized".to_owned(),
                                };
                                self.save(&job)?;
                                return Ok(());
                            }
                            E3Stage::Failed => {
                                job.state = JobState::Failed {
                                message: "the E3 failed before its aggregate ciphertext was published"
                                    .to_owned(),
                            };
                                self.save(&job)?;
                                return Ok(());
                            }
                            E3Stage::None | E3Stage::Requested | E3Stage::CommitteeFinalized => {
                                anyhow::bail!("the E3 is not ready for its aggregate ciphertext");
                            }
                            stage => {
                                anyhow::bail!(
                                    "unsupported E3 stage {stage:?} while publishing an aggregate ciphertext"
                                );
                            }
                        }
                        let receipt = contract
                            .publish_ciphertext_output(
                                e3_id,
                                B256::from(job.content_hash),
                                B256::from(*ciphertext_commitment),
                                Bytes::copy_from_slice(compute_proof),
                                Bytes::copy_from_slice(ethereum_payload),
                            )
                            .await
                            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                        job.state = JobState::Submitted {
                            transaction_hash: receipt.transaction_hash.to_string(),
                        };
                        self.save(&job)?;
                    }
                }
            }
            JobState::Submitted { .. } | JobState::Failed { .. } => {}
        }
        Ok(())
    }

    fn ethereum_payload(
        &self,
        job: &AvailabilityJob,
        availability_proof: Vec<u8>,
    ) -> anyhow::Result<Vec<u8>> {
        match &job.kind {
            JobKind::Input {
                staged_envelope, ..
            } => {
                let mut envelope = InputEnvelope::abi_decode(staged_envelope)?;
                envelope.availabilityProof = availability_proof.into();
                Ok(envelope.abi_encode())
            }
            JobKind::Output { .. } => Ok(availability_proof),
        }
    }

    fn job_id(
        &self,
        domain: &[u8],
        e3_id: &str,
        content_hash: B256,
        request_identity: &[u8],
    ) -> String {
        let mut identity = Vec::with_capacity(domain.len() + e3_id.len() + 64);
        identity.extend_from_slice(domain);
        identity.extend_from_slice(e3_id.as_bytes());
        identity.extend_from_slice(content_hash.as_slice());
        identity.extend_from_slice(keccak256(request_identity).as_slice());
        format!("0x{}", hex::encode(keccak256(identity)))
    }

    async fn chain_timestamp(&self) -> anyhow::Result<u64> {
        let block = tokio::time::timeout(Duration::from_secs(15), async {
            let provider = ProviderBuilder::new().connect(&self.http_rpc_url).await?;
            provider.get_block_by_number(BlockNumberOrTag::Latest).await
        })
        .await
        .map_err(|_| anyhow::anyhow!("timed out while reading the Ethereum head"))??
        .ok_or_else(|| anyhow::anyhow!("the Ethereum RPC returned no latest block"))?;
        Ok(block.header.timestamp)
    }

    async fn input_is_published(&self, job: &AvailabilityJob) -> anyhow::Result<bool> {
        let JobKind::Input {
            e3_id,
            staged_envelope,
            ..
        } = &job.kind
        else {
            return Ok(false);
        };
        let envelope = InputEnvelope::abi_decode(staged_envelope)?;
        let contract = CRISPContract::new(
            &self.http_rpc_url,
            &self.private_key,
            &self.e3_program_address,
        )
        .await
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        contract
            .is_input_published(
                e3_id_to_u256(e3_id)?,
                envelope.encryptedVoteHash,
                envelope.encryptedVoteCommitment,
                envelope.slotAddress,
                envelope.parentIndexPlusOne.to::<u64>(),
            )
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()))
    }

    async fn ethereum_publication_exists(&self, job: &AvailabilityJob) -> anyhow::Result<bool> {
        match &job.kind {
            JobKind::Input { .. } => self.input_is_published(job).await,
            JobKind::Output { e3_id, .. } => {
                let contract = InterfoldContractFactory::create_read(
                    &self.http_rpc_url,
                    &self.interfold_address,
                )
                .await
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                let stage = contract
                    .get_e3_stage(e3_id_to_u256(e3_id)?)
                    .await
                    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                Ok(matches!(
                    stage,
                    E3Stage::CiphertextReady | E3Stage::Complete
                ))
            }
        }
    }

    fn pending_ids(&self) -> Vec<String> {
        self.jobs
            .iter()
            .filter_map(|entry| {
                let (_, value) = entry.ok()?;
                let job: AvailabilityJob = serde_json::from_slice(&value).ok()?;
                let terminal = matches!(
                    job.state,
                    JobState::Submitted { .. } | JobState::Failed { .. }
                );
                (!terminal).then_some(job.id)
            })
            .collect()
    }

    fn load(&self, id: &str) -> anyhow::Result<Option<AvailabilityJob>> {
        self.jobs
            .get(id.as_bytes())?
            .map(|bytes| serde_json::from_slice(&bytes).map_err(Into::into))
            .transpose()
    }

    fn load_required(&self, id: &str) -> anyhow::Result<AvailabilityJob> {
        self.load(id)?
            .ok_or_else(|| anyhow::anyhow!("data-availability job {id} does not exist"))
    }

    fn save(&self, job: &AvailabilityJob) -> anyhow::Result<()> {
        self.jobs
            .insert(job.id.as_bytes(), serde_json::to_vec(job)?)?;
        self.jobs.flush()?;
        Ok(())
    }
}
