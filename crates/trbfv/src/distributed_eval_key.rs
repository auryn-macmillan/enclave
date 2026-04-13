// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{helpers::deserialize_secret_key, TrBFVConfig};
use anyhow::{anyhow, ensure, Context, Result};
use e3_utils::utility_types::ArcBytes;
use fhe::{
    bfv::{
        traits::TryConvertFrom as BfvTryConvertFrom, BfvParameters, EvaluationKey, KeySwitchingKey,
        RelinearizationKey, SecretKey,
    },
    mbfv::CommonRandomPoly,
    proto::bfv::{
        EvaluationKey as EvaluationKeyProto, GaloisKey as GaloisKeyProto,
        KeySwitchingKey as KeySwitchingKeyProto,
    },
};
use fhe_math::{
    rns::RnsContext,
    rq::{
        switcher::Switcher, traits::TryConvertFrom as PolyTryConvertFrom, Poly, Representation,
        SubstitutionExponent,
    },
};
use fhe_traits::{DeserializeParametrized, DeserializeWithContext, Serialize};
use prost::Message;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize as SerdeSerialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use zeroize::Zeroizing;

const SUPPORTED_LEVEL: u64 = 0;
const DOMAIN_GALOIS_C1: &[u8] = b"trbfv/eval-key/galois/c1";
const DOMAIN_RELIN_CRP: &[u8] = b"trbfv/eval-key/relin/crp";
const DOMAIN_AUDIT_CRS_GALOIS_V1: &[u8] = b"trbfv/eval-key/audit/v1/crs/galois";
const DOMAIN_AUDIT_CRS_RELIN_V1: &[u8] = b"trbfv/eval-key/audit/v1/crs/relin";
const DOMAIN_AUDIT_ADDITIVE_SHARE_COMMITMENT_V1: &[u8] =
    b"trbfv/eval-key/audit/v1/commitment/additive-share";
const DOMAIN_AUDIT_RELIN_EPHEMERAL_COMMITMENT_V1: &[u8] =
    b"trbfv/eval-key/audit/v1/commitment/relin-ephemeral-u";
const DOMAIN_AUDIT_GALOIS_SHARE_DIGEST_V1: &[u8] = b"trbfv/eval-key/audit/v1/digest/galois-share";
const DOMAIN_AUDIT_RELIN_ROUND1_SHARE_DIGEST_V1: &[u8] =
    b"trbfv/eval-key/audit/v1/digest/relin-round1-share";
const DOMAIN_AUDIT_RELIN_ROUND1_AGGREGATE_DIGEST_V1: &[u8] =
    b"trbfv/eval-key/audit/v1/digest/relin-round1-aggregate";
const DOMAIN_AUDIT_RELIN_ROUND2_SHARE_DIGEST_V1: &[u8] =
    b"trbfv/eval-key/audit/v1/digest/relin-round2-share";
const DOMAIN_AUDIT_GALOIS_KEY_DIGEST_V1: &[u8] = b"trbfv/eval-key/audit/v1/digest/galois-key";
const DOMAIN_AUDIT_EVALUATION_KEY_DIGEST_V1: &[u8] =
    b"trbfv/eval-key/audit/v1/digest/evaluation-key";
const DOMAIN_AUDIT_RELIN_KEY_DIGEST_V1: &[u8] = b"trbfv/eval-key/audit/v1/digest/relin-key";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, SerdeSerialize, Deserialize)]
pub struct DistributedEvalKeyAuditHash {
    pub bytes: [u8; 32],
}

impl DistributedEvalKeyAuditHash {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, SerdeSerialize, Deserialize)]
pub struct DistributedGaloisKeyShareAuditV1 {
    pub crs_binding_hash: DistributedEvalKeyAuditHash,
    pub additive_share_commitment_hash: DistributedEvalKeyAuditHash,
    pub galois_share_digest: DistributedEvalKeyAuditHash,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, SerdeSerialize, Deserialize)]
pub struct DistributedRelinRound1ShareAuditV1 {
    pub crs_binding_hash: DistributedEvalKeyAuditHash,
    pub additive_share_commitment_hash: DistributedEvalKeyAuditHash,
    pub relin_ephemeral_u_commitment_hash: DistributedEvalKeyAuditHash,
    pub relin_round1_share_digest: DistributedEvalKeyAuditHash,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, SerdeSerialize, Deserialize)]
pub struct DistributedRelinRound1AggregateAuditV1 {
    pub crs_binding_hash: DistributedEvalKeyAuditHash,
    pub relin_round1_aggregate_digest: DistributedEvalKeyAuditHash,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, SerdeSerialize, Deserialize)]
pub struct DistributedRelinRound2ShareAuditV1 {
    pub crs_binding_hash: DistributedEvalKeyAuditHash,
    pub additive_share_commitment_hash: DistributedEvalKeyAuditHash,
    pub relin_ephemeral_u_commitment_hash: DistributedEvalKeyAuditHash,
    pub round1_aggregate_digest: DistributedEvalKeyAuditHash,
    pub relin_round2_share_digest: DistributedEvalKeyAuditHash,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, SerdeSerialize, Deserialize)]
pub struct DistributedRelinRound1SecretStateAuditV1 {
    pub crs_binding_hash: DistributedEvalKeyAuditHash,
    pub additive_share_commitment_hash: DistributedEvalKeyAuditHash,
    pub relin_ephemeral_u_commitment_hash: DistributedEvalKeyAuditHash,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, SerdeSerialize, Deserialize)]
pub struct AggregatedDistributedGaloisKeyAuditV1 {
    pub crs_binding_hash: DistributedEvalKeyAuditHash,
    pub galois_key_digest: DistributedEvalKeyAuditHash,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, SerdeSerialize, Deserialize)]
pub struct AggregatedDistributedEvaluationKeyAuditV1 {
    pub evaluation_key_digest: DistributedEvalKeyAuditHash,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, SerdeSerialize, Deserialize)]
pub struct AggregatedDistributedRelinKeyAuditV1 {
    pub crs_binding_hash: DistributedEvalKeyAuditHash,
    pub relin_round1_aggregate_digest: DistributedEvalKeyAuditHash,
    pub relinearization_key_digest: DistributedEvalKeyAuditHash,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, SerdeSerialize, Deserialize)]
pub struct EvalKeyRootSeed {
    pub bytes: [u8; 32],
}

impl EvalKeyRootSeed {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, SerdeSerialize, Deserialize)]
pub struct DistributedGaloisKeyShare {
    pub exponent: u64,
    pub ciphertext_level: u64,
    pub evaluation_key_level: u64,
    pub c0_share: Vec<ArcBytes>,
    pub audit: DistributedGaloisKeyShareAuditV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, SerdeSerialize, Deserialize)]
pub struct DistributedGaloisKeyShareProofWitness {
    pub secret_key_share: ArcBytes,
    pub substituted_secret_share: ArcBytes,
    pub transformed_secret_share: ArcBytes,
    pub c1_share: ArcBytes,
    pub error_share: ArcBytes,
    pub component_index: u64,
    pub garner_coefficient_decimal: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, SerdeSerialize, Deserialize)]
pub struct DistributedRelinRound1Share {
    pub ciphertext_level: u64,
    pub key_level: u64,
    pub h0: Vec<ArcBytes>,
    pub h1: Vec<ArcBytes>,
    pub audit: DistributedRelinRound1ShareAuditV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, SerdeSerialize, Deserialize)]
pub struct DistributedRelinRound1ShareProofWitness {
    pub secret_key_share: ArcBytes,
    pub ephemeral_u_share: ArcBytes,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, SerdeSerialize, Deserialize)]
pub struct DistributedRelinRound1Aggregate {
    pub ciphertext_level: u64,
    pub key_level: u64,
    pub h0: Vec<ArcBytes>,
    pub h1: Vec<ArcBytes>,
    pub audit: DistributedRelinRound1AggregateAuditV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, SerdeSerialize, Deserialize)]
pub struct DistributedRelinRound2Share {
    pub ciphertext_level: u64,
    pub key_level: u64,
    pub h0: Vec<ArcBytes>,
    pub h1: Vec<ArcBytes>,
    pub audit: DistributedRelinRound2ShareAuditV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, SerdeSerialize, Deserialize)]
pub struct DistributedRelinRound2ShareProofWitness {
    pub secret_key_share: ArcBytes,
    pub ephemeral_u_share: ArcBytes,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, SerdeSerialize, Deserialize)]
pub struct DistributedRelinRound1SecretState {
    pub ciphertext_level: u64,
    pub key_level: u64,
    pub ephemeral_u_share: ArcBytes,
    pub audit: DistributedRelinRound1SecretStateAuditV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, SerdeSerialize, Deserialize)]
pub struct GenerateDistributedGaloisKeyShareRequest {
    pub trbfv_config: TrBFVConfig,
    pub root_seed: EvalKeyRootSeed,
    pub secret_key_share: ArcBytes,
    pub exponent: u64,
    pub ciphertext_level: u64,
    pub evaluation_key_level: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, SerdeSerialize, Deserialize)]
pub struct GenerateDistributedGaloisKeyShareResponse {
    pub share: DistributedGaloisKeyShare,
    pub proof_witness: DistributedGaloisKeyShareProofWitness,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, SerdeSerialize, Deserialize)]
pub struct AggregateDistributedGaloisKeyRequest {
    pub trbfv_config: TrBFVConfig,
    pub root_seed: EvalKeyRootSeed,
    pub exponent: u64,
    pub ciphertext_level: u64,
    pub evaluation_key_level: u64,
    pub shares: Vec<DistributedGaloisKeyShare>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, SerdeSerialize, Deserialize)]
pub struct AggregateDistributedGaloisKeyResponse {
    pub exponent: u64,
    pub galois_key: ArcBytes,
    pub audit: AggregatedDistributedGaloisKeyAuditV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, SerdeSerialize, Deserialize)]
pub struct AggregateDistributedEvaluationKeyRequest {
    pub trbfv_config: TrBFVConfig,
    pub ciphertext_level: u64,
    pub evaluation_key_level: u64,
    pub galois_keys: Vec<ArcBytes>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, SerdeSerialize, Deserialize)]
pub struct AggregateDistributedEvaluationKeyResponse {
    pub evaluation_key: ArcBytes,
    pub audit: AggregatedDistributedEvaluationKeyAuditV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, SerdeSerialize, Deserialize)]
pub struct GenerateDistributedRelinRound1Request {
    pub trbfv_config: TrBFVConfig,
    pub root_seed: EvalKeyRootSeed,
    pub secret_key_share: ArcBytes,
    pub ciphertext_level: u64,
    pub key_level: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, SerdeSerialize, Deserialize)]
pub struct GenerateDistributedRelinRound1Response {
    pub share: DistributedRelinRound1Share,
    pub helper: DistributedRelinRound1SecretState,
    pub proof_witness: DistributedRelinRound1ShareProofWitness,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, SerdeSerialize, Deserialize)]
pub struct AggregateDistributedRelinRound1Request {
    pub trbfv_config: TrBFVConfig,
    pub ciphertext_level: u64,
    pub key_level: u64,
    pub shares: Vec<DistributedRelinRound1Share>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, SerdeSerialize, Deserialize)]
pub struct AggregateDistributedRelinRound1Response {
    pub aggregate: DistributedRelinRound1Aggregate,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, SerdeSerialize, Deserialize)]
pub struct GenerateDistributedRelinRound2Request {
    pub trbfv_config: TrBFVConfig,
    pub secret_key_share: ArcBytes,
    pub helper: DistributedRelinRound1SecretState,
    pub round1_aggregate: DistributedRelinRound1Aggregate,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, SerdeSerialize, Deserialize)]
pub struct GenerateDistributedRelinRound2Response {
    pub share: DistributedRelinRound2Share,
    pub proof_witness: DistributedRelinRound2ShareProofWitness,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, SerdeSerialize, Deserialize)]
pub struct AggregateDistributedRelinKeyRequest {
    pub trbfv_config: TrBFVConfig,
    pub round1_aggregate: DistributedRelinRound1Aggregate,
    pub shares: Vec<DistributedRelinRound2Share>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, SerdeSerialize, Deserialize)]
pub struct AggregateDistributedRelinKeyResponse {
    pub relinearization_key: ArcBytes,
    pub audit: AggregatedDistributedRelinKeyAuditV1,
}

pub fn generate_distributed_galois_key_share<R: RngCore + CryptoRng>(
    rng: &mut R,
    req: GenerateDistributedGaloisKeyShareRequest,
) -> Result<GenerateDistributedGaloisKeyShareResponse> {
    validate_supported_galois_levels(req.ciphertext_level, req.evaluation_key_level)?;

    let params = req.trbfv_config.params();
    let sk_share = deserialize_secret_key(&req.secret_key_share, &params)?;
    let ctx = params.ctx_at_level(SUPPORTED_LEVEL as usize)?.clone();
    let exponent = req.exponent as usize;
    let element = SubstitutionExponent::new(&ctx, exponent).map_err(|err| anyhow!("{err}"))?;
    let switcher = Switcher::new(&ctx, &ctx)?;

    let s = Zeroizing::new(Poly::try_convert_from(
        sk_share.coeffs.as_ref(),
        &ctx,
        false,
        Representation::PowerBasis,
    )?);
    let s_sub = Zeroizing::new(s.substitute(&element)?);
    let mut from = Zeroizing::new(s_sub.mod_switch_to(&switcher)?);
    from.change_representation(Representation::PowerBasis);

    let mut s_ntt = Zeroizing::new(Poly::try_convert_from(
        sk_share.coeffs.as_ref(),
        &ctx,
        false,
        Representation::PowerBasis,
    )?);
    s_ntt.change_representation(Representation::Ntt);

    let rns = RnsContext::new(&params.moduli()[..ctx.moduli().len()])?;
    let crs_binding_hash = galois_crs_binding_hash(
        &params,
        &req.root_seed,
        req.exponent,
        req.ciphertext_level,
        req.evaluation_key_level,
    )?;
    let additive_share_commitment_hash =
        additive_share_commitment_hash(crs_binding_hash, &req.secret_key_share);
    let mut first_c1_share: Option<ArcBytes> = None;
    let mut first_error_share: Option<ArcBytes> = None;
    let mut first_garner_coefficient: Option<String> = None;
    let c0_share = (0..ctx.moduli().len())
        .map(|index| {
            let c1 = derive_galois_c1_poly(&params, &req.root_seed, exponent, index)?;
            if index == 0 {
                first_c1_share = Some(ArcBytes::from_bytes(&c1.to_bytes()));
            }
            let mut a_s = Zeroizing::new(c1.clone());
            a_s.disallow_variable_time_computations();
            a_s.change_representation(Representation::Ntt);
            *a_s.as_mut() *= s_ntt.as_ref();
            a_s.change_representation(Representation::PowerBasis);

            let mut b = Poly::small(&ctx, Representation::PowerBasis, params.variance(), rng)?;
            if index == 0 {
                first_error_share = Some(ArcBytes::from_bytes(&b.to_bytes()));
            }
            b -= a_s.as_ref();
            let garner = rns
                .get_garner(index)
                .ok_or_else(|| anyhow!("missing Garner coefficient at index {index}"))?;
            if index == 0 {
                first_garner_coefficient = Some(garner.to_string());
            }
            b += &Zeroizing::new(garner * from.as_ref());
            unsafe { b.allow_variable_time_computations() }
            Ok(ArcBytes::from_bytes(&b.to_bytes()))
        })
        .collect::<Result<Vec<_>>>()?;
    let share_audit = DistributedGaloisKeyShareAuditV1 {
        crs_binding_hash,
        additive_share_commitment_hash,
        galois_share_digest: galois_share_digest(
            req.exponent,
            req.ciphertext_level,
            req.evaluation_key_level,
            &c0_share,
        ),
    };

    Ok(GenerateDistributedGaloisKeyShareResponse {
        share: DistributedGaloisKeyShare {
            exponent: req.exponent,
            ciphertext_level: req.ciphertext_level,
            evaluation_key_level: req.evaluation_key_level,
            c0_share,
            audit: share_audit,
        },
        proof_witness: DistributedGaloisKeyShareProofWitness {
            secret_key_share: req.secret_key_share,
            substituted_secret_share: ArcBytes::from_bytes(&s_sub.to_bytes()),
            transformed_secret_share: ArcBytes::from_bytes(&from.to_bytes()),
            c1_share: first_c1_share.ok_or_else(|| anyhow!("missing first galois c1 share"))?,
            error_share: first_error_share
                .ok_or_else(|| anyhow!("missing first galois error share"))?,
            component_index: 0,
            garner_coefficient_decimal: first_garner_coefficient
                .ok_or_else(|| anyhow!("missing first galois garner coefficient"))?,
        },
    })
}

pub fn aggregate_distributed_galois_key(
    req: AggregateDistributedGaloisKeyRequest,
) -> Result<AggregateDistributedGaloisKeyResponse> {
    validate_supported_galois_levels(req.ciphertext_level, req.evaluation_key_level)?;
    ensure!(
        !req.shares.is_empty(),
        "at least one galois share is required"
    );

    let params = req.trbfv_config.params();
    let ctx = params.ctx_at_level(SUPPORTED_LEVEL as usize)?.clone();
    let expected_components = ctx.moduli().len();
    let expected_crs_binding_hash = galois_crs_binding_hash(
        &params,
        &req.root_seed,
        req.exponent,
        req.ciphertext_level,
        req.evaluation_key_level,
    )?;

    for share in &req.shares {
        ensure!(
            share.exponent == req.exponent,
            "galois share exponent mismatch"
        );
        ensure!(
            share.ciphertext_level == req.ciphertext_level,
            "galois share ciphertext level mismatch"
        );
        ensure!(
            share.evaluation_key_level == req.evaluation_key_level,
            "galois share evaluation key level mismatch"
        );
        ensure!(
            share.c0_share.len() == expected_components,
            "galois share component count mismatch"
        );
        ensure!(
            share.audit.crs_binding_hash == expected_crs_binding_hash,
            "galois share CRS binding mismatch"
        );
        ensure!(
            share.audit.galois_share_digest
                == galois_share_digest(
                    share.exponent,
                    share.ciphertext_level,
                    share.evaluation_key_level,
                    &share.c0_share,
                ),
            "galois share audit digest mismatch"
        );
    }

    let mut c0 = deserialize_poly_vec(&req.shares[0].c0_share, &ctx)?;
    for share in req.shares.iter().skip(1) {
        for (acc, next) in c0
            .iter_mut()
            .zip(deserialize_poly_vec(&share.c0_share, &ctx)?)
        {
            *acc += &next;
        }
    }
    for poly in &mut c0 {
        poly.change_representation(Representation::NttShoup);
    }

    let c1 = (0..expected_components)
        .map(|index| derive_galois_c1_poly(&params, &req.root_seed, req.exponent as usize, index))
        .collect::<Result<Vec<_>>>()?;

    let ksk = new_level_zero_ksk(&params, c0, c1);
    let gk_proto = GaloisKeyProto {
        exponent: req.exponent as u32,
        ksk: Some(KeySwitchingKeyProto::from(&ksk)),
    };

    EvaluationKey::try_convert_from(
        &EvaluationKeyProto {
            gk: vec![gk_proto.clone()],
            ciphertext_level: req.ciphertext_level as u32,
            evaluation_key_level: req.evaluation_key_level as u32,
        },
        &params,
    )?;

    Ok(AggregateDistributedGaloisKeyResponse {
        exponent: req.exponent,
        galois_key: ArcBytes::from_bytes(&gk_proto.encode_to_vec()),
        audit: AggregatedDistributedGaloisKeyAuditV1 {
            crs_binding_hash: expected_crs_binding_hash,
            galois_key_digest: galois_key_digest(req.exponent, &gk_proto),
        },
    })
}

pub fn aggregate_distributed_evaluation_key(
    req: AggregateDistributedEvaluationKeyRequest,
) -> Result<AggregateDistributedEvaluationKeyResponse> {
    validate_supported_galois_levels(req.ciphertext_level, req.evaluation_key_level)?;
    ensure!(
        !req.galois_keys.is_empty(),
        "at least one galois key is required"
    );

    let params = req.trbfv_config.params();
    let gk = req
        .galois_keys
        .iter()
        .map(|bytes| decode_galois_key_proto(bytes))
        .collect::<Result<Vec<_>>>()?;

    let proto = EvaluationKeyProto {
        gk,
        ciphertext_level: req.ciphertext_level as u32,
        evaluation_key_level: req.evaluation_key_level as u32,
    };

    let key = EvaluationKey::try_convert_from(&proto, &params)?;
    let evaluation_key = key.to_bytes();
    Ok(AggregateDistributedEvaluationKeyResponse {
        evaluation_key: ArcBytes::from_bytes(&evaluation_key),
        audit: AggregatedDistributedEvaluationKeyAuditV1 {
            evaluation_key_digest: evaluation_key_digest(&evaluation_key),
        },
    })
}

pub fn generate_distributed_relin_round1<R: RngCore + CryptoRng>(
    rng: &mut R,
    req: GenerateDistributedRelinRound1Request,
) -> Result<GenerateDistributedRelinRound1Response> {
    validate_supported_relin_levels(req.ciphertext_level, req.key_level)?;

    let params = req.trbfv_config.params();
    let sk_share = deserialize_secret_key(&req.secret_key_share, &params)?;
    let ctx = params.ctx_at_level(SUPPORTED_LEVEL as usize)?.clone();
    ensure!(
        ctx.moduli().len() > 1,
        "relinearization requires at least two moduli"
    );

    let crp = derive_relin_crp_vector(&params, &req.root_seed)?;
    let crs_binding_hash =
        relin_crs_binding_hash(&params, &req.root_seed, req.ciphertext_level, req.key_level)?;
    let u = Poly::small(&ctx, Representation::Ntt, params.variance(), rng)?;
    let u = Zeroizing::new(u);
    let ephemeral_u_share = ArcBytes::from_bytes(&u.to_bytes());
    let additive_share_commitment_hash =
        additive_share_commitment_hash(crs_binding_hash, &req.secret_key_share);
    let relin_ephemeral_u_commitment_hash =
        relin_ephemeral_u_commitment_hash(crs_binding_hash, &ephemeral_u_share);
    let s_power = Zeroizing::new(Poly::try_convert_from(
        sk_share.coeffs.as_ref(),
        &ctx,
        false,
        Representation::PowerBasis,
    )?);
    let mut s_ntt = Zeroizing::new(s_power.as_ref().clone());
    s_ntt.change_representation(Representation::Ntt);
    let rns = RnsContext::new(&params.moduli()[..crp.len()])?;

    let h0 = crp
        .iter()
        .enumerate()
        .map(|(index, a)| {
            let garner = rns
                .get_garner(index)
                .ok_or_else(|| anyhow!("missing Garner coefficient at index {index}"))?;
            let mut w_s = Zeroizing::new(garner * s_power.as_ref());
            w_s.change_representation(Representation::Ntt);

            let e = Zeroizing::new(Poly::small(
                &ctx,
                Representation::Ntt,
                params.variance(),
                rng,
            )?);
            let mut h = -a.poly().clone();
            h.disallow_variable_time_computations();
            h.change_representation(Representation::Ntt);
            h *= u.as_ref();
            h += w_s.as_ref();
            h += e.as_ref();
            Ok(ArcBytes::from_bytes(&h.to_bytes()))
        })
        .collect::<Result<Vec<_>>>()?;

    let h1 = crp
        .iter()
        .map(|a| {
            let e = Zeroizing::new(Poly::small(
                &ctx,
                Representation::Ntt,
                params.variance(),
                rng,
            )?);
            let mut h = a.poly().clone();
            h.disallow_variable_time_computations();
            h.change_representation(Representation::Ntt);
            h *= s_ntt.as_ref();
            h += e.as_ref();
            Ok(ArcBytes::from_bytes(&h.to_bytes()))
        })
        .collect::<Result<Vec<_>>>()?;
    let share_audit = DistributedRelinRound1ShareAuditV1 {
        crs_binding_hash,
        additive_share_commitment_hash,
        relin_ephemeral_u_commitment_hash,
        relin_round1_share_digest: relin_round1_share_digest(
            req.ciphertext_level,
            req.key_level,
            &h0,
            &h1,
        ),
    };
    let helper_audit = DistributedRelinRound1SecretStateAuditV1 {
        crs_binding_hash,
        additive_share_commitment_hash,
        relin_ephemeral_u_commitment_hash,
    };

    Ok(GenerateDistributedRelinRound1Response {
        share: DistributedRelinRound1Share {
            ciphertext_level: req.ciphertext_level,
            key_level: req.key_level,
            h0,
            h1,
            audit: share_audit,
        },
        helper: DistributedRelinRound1SecretState {
            ciphertext_level: req.ciphertext_level,
            key_level: req.key_level,
            ephemeral_u_share,
            audit: helper_audit,
        },
        proof_witness: DistributedRelinRound1ShareProofWitness {
            secret_key_share: req.secret_key_share,
            ephemeral_u_share: ArcBytes::from_bytes(&u.to_bytes()),
        },
    })
}

pub fn aggregate_distributed_relin_round1(
    req: AggregateDistributedRelinRound1Request,
) -> Result<AggregateDistributedRelinRound1Response> {
    validate_supported_relin_levels(req.ciphertext_level, req.key_level)?;
    ensure!(
        !req.shares.is_empty(),
        "at least one relin round1 share is required"
    );

    let params = req.trbfv_config.params();
    let ctx = params.ctx_at_level(SUPPORTED_LEVEL as usize)?.clone();
    let expected_components = ctx.moduli().len();
    let expected_crs_binding_hash = req
        .shares
        .first()
        .ok_or_else(|| anyhow!("at least one relin round1 share is required"))?
        .audit
        .crs_binding_hash;

    for share in &req.shares {
        ensure!(
            share.ciphertext_level == req.ciphertext_level,
            "relin round1 ciphertext level mismatch"
        );
        ensure!(
            share.key_level == req.key_level,
            "relin round1 key level mismatch"
        );
        ensure!(
            share.h0.len() == expected_components,
            "relin round1 h0 size mismatch"
        );
        ensure!(
            share.h1.len() == expected_components,
            "relin round1 h1 size mismatch"
        );
        ensure!(
            share.audit.crs_binding_hash == expected_crs_binding_hash,
            "relin round1 share CRS binding mismatch"
        );
        ensure!(
            share.audit.relin_round1_share_digest
                == relin_round1_share_digest(
                    share.ciphertext_level,
                    share.key_level,
                    &share.h0,
                    &share.h1,
                ),
            "relin round1 share audit digest mismatch"
        );
    }

    let mut h0 = deserialize_poly_vec(&req.shares[0].h0, &ctx)?;
    let mut h1 = deserialize_poly_vec(&req.shares[0].h1, &ctx)?;
    for share in req.shares.iter().skip(1) {
        for (acc, next) in h0.iter_mut().zip(deserialize_poly_vec(&share.h0, &ctx)?) {
            *acc += &next;
        }
        for (acc, next) in h1.iter_mut().zip(deserialize_poly_vec(&share.h1, &ctx)?) {
            *acc += &next;
        }
    }
    let h0 = serialize_poly_vec(h0);
    let h1 = serialize_poly_vec(h1);

    Ok(AggregateDistributedRelinRound1Response {
        aggregate: DistributedRelinRound1Aggregate {
            ciphertext_level: req.ciphertext_level,
            key_level: req.key_level,
            h0: h0.clone(),
            h1: h1.clone(),
            audit: DistributedRelinRound1AggregateAuditV1 {
                crs_binding_hash: expected_crs_binding_hash,
                relin_round1_aggregate_digest: relin_round1_aggregate_digest(
                    req.ciphertext_level,
                    req.key_level,
                    &h0,
                    &h1,
                ),
            },
        },
    })
}

pub fn generate_distributed_relin_round2<R: RngCore + CryptoRng>(
    rng: &mut R,
    req: GenerateDistributedRelinRound2Request,
) -> Result<GenerateDistributedRelinRound2Response> {
    validate_supported_relin_levels(
        req.round1_aggregate.ciphertext_level,
        req.round1_aggregate.key_level,
    )?;
    ensure!(
        req.helper.ciphertext_level == req.round1_aggregate.ciphertext_level,
        "relin helper ciphertext level mismatch"
    );
    ensure!(
        req.helper.key_level == req.round1_aggregate.key_level,
        "relin helper key level mismatch"
    );
    ensure!(
        req.helper.audit.crs_binding_hash == req.round1_aggregate.audit.crs_binding_hash,
        "relin helper CRS binding mismatch"
    );
    ensure!(
        req.helper.audit.relin_ephemeral_u_commitment_hash
            == relin_ephemeral_u_commitment_hash(
                req.helper.audit.crs_binding_hash,
                &req.helper.ephemeral_u_share,
            ),
        "relin helper ephemeral commitment mismatch"
    );
    ensure!(
        req.helper.audit.additive_share_commitment_hash
            == additive_share_commitment_hash(
                req.helper.audit.crs_binding_hash,
                &req.secret_key_share,
            ),
        "relin helper additive share commitment mismatch"
    );
    ensure!(
        req.round1_aggregate.audit.relin_round1_aggregate_digest
            == relin_round1_aggregate_digest(
                req.round1_aggregate.ciphertext_level,
                req.round1_aggregate.key_level,
                &req.round1_aggregate.h0,
                &req.round1_aggregate.h1,
            ),
        "relin round1 aggregate audit digest mismatch"
    );

    let params = req.trbfv_config.params();
    let sk_share = deserialize_secret_key(&req.secret_key_share, &params)?;
    let ctx = params.ctx_at_level(SUPPORTED_LEVEL as usize)?.clone();
    let aggregated_h0 = deserialize_poly_vec(&req.round1_aggregate.h0, &ctx)?;
    let aggregated_h1 = deserialize_poly_vec(&req.round1_aggregate.h1, &ctx)?;
    let u = Poly::from_bytes(&req.helper.ephemeral_u_share, &ctx)?;

    let mut s_ntt = Zeroizing::new(Poly::try_convert_from(
        sk_share.coeffs.as_ref(),
        &ctx,
        false,
        Representation::PowerBasis,
    )?);
    s_ntt.change_representation(Representation::Ntt);
    let u_minus_s = Zeroizing::new(&u - s_ntt.as_ref());

    let h0 = aggregated_h0
        .iter()
        .map(|poly| {
            let e = Zeroizing::new(Poly::small(
                &ctx,
                Representation::Ntt,
                params.variance(),
                rng,
            )?);
            let mut h = poly.clone();
            h.disallow_variable_time_computations();
            h.change_representation(Representation::Ntt);
            h *= s_ntt.as_ref();
            h += e.as_ref();
            Ok(ArcBytes::from_bytes(&h.to_bytes()))
        })
        .collect::<Result<Vec<_>>>()?;

    let h1 = aggregated_h1
        .iter()
        .map(|poly| {
            let e = Zeroizing::new(Poly::small(
                &ctx,
                Representation::Ntt,
                params.variance(),
                rng,
            )?);
            let mut h = poly.clone();
            h.disallow_variable_time_computations();
            h.change_representation(Representation::Ntt);
            h *= u_minus_s.as_ref();
            h += e.as_ref();
            Ok(ArcBytes::from_bytes(&h.to_bytes()))
        })
        .collect::<Result<Vec<_>>>()?;
    let share_audit = DistributedRelinRound2ShareAuditV1 {
        crs_binding_hash: req.round1_aggregate.audit.crs_binding_hash,
        additive_share_commitment_hash: additive_share_commitment_hash(
            req.round1_aggregate.audit.crs_binding_hash,
            &req.secret_key_share,
        ),
        relin_ephemeral_u_commitment_hash: req.helper.audit.relin_ephemeral_u_commitment_hash,
        round1_aggregate_digest: req.round1_aggregate.audit.relin_round1_aggregate_digest,
        relin_round2_share_digest: relin_round2_share_digest(
            req.round1_aggregate.ciphertext_level,
            req.round1_aggregate.key_level,
            &h0,
            &h1,
        ),
    };

    Ok(GenerateDistributedRelinRound2Response {
        share: DistributedRelinRound2Share {
            ciphertext_level: req.round1_aggregate.ciphertext_level,
            key_level: req.round1_aggregate.key_level,
            h0,
            h1,
            audit: share_audit,
        },
        proof_witness: DistributedRelinRound2ShareProofWitness {
            secret_key_share: req.secret_key_share,
            ephemeral_u_share: req.helper.ephemeral_u_share,
        },
    })
}

pub fn aggregate_distributed_relin_key(
    req: AggregateDistributedRelinKeyRequest,
) -> Result<AggregateDistributedRelinKeyResponse> {
    validate_supported_relin_levels(
        req.round1_aggregate.ciphertext_level,
        req.round1_aggregate.key_level,
    )?;
    ensure!(
        !req.shares.is_empty(),
        "at least one relin round2 share is required"
    );

    let params = req.trbfv_config.params();
    let ctx = params.ctx_at_level(SUPPORTED_LEVEL as usize)?.clone();
    let expected_components = ctx.moduli().len();
    ensure!(
        req.round1_aggregate.audit.relin_round1_aggregate_digest
            == relin_round1_aggregate_digest(
                req.round1_aggregate.ciphertext_level,
                req.round1_aggregate.key_level,
                &req.round1_aggregate.h0,
                &req.round1_aggregate.h1,
            ),
        "relin round1 aggregate audit digest mismatch"
    );
    for share in &req.shares {
        ensure!(
            share.ciphertext_level == req.round1_aggregate.ciphertext_level,
            "relin round2 ciphertext level mismatch"
        );
        ensure!(
            share.key_level == req.round1_aggregate.key_level,
            "relin round2 key level mismatch"
        );
        ensure!(
            share.h0.len() == expected_components,
            "relin round2 h0 size mismatch"
        );
        ensure!(
            share.h1.len() == expected_components,
            "relin round2 h1 size mismatch"
        );
        ensure!(
            share.audit.crs_binding_hash == req.round1_aggregate.audit.crs_binding_hash,
            "relin round2 share CRS binding mismatch"
        );
        ensure!(
            share.audit.round1_aggregate_digest
                == req.round1_aggregate.audit.relin_round1_aggregate_digest,
            "relin round2 share round1 aggregate linkage mismatch"
        );
        ensure!(
            share.audit.relin_round2_share_digest
                == relin_round2_share_digest(
                    share.ciphertext_level,
                    share.key_level,
                    &share.h0,
                    &share.h1,
                ),
            "relin round2 share audit digest mismatch"
        );
    }

    let mut r0 = deserialize_poly_vec(&req.shares[0].h0, &ctx)?;
    let mut r1 = deserialize_poly_vec(&req.shares[0].h1, &ctx)?;
    for share in req.shares.iter().skip(1) {
        for (acc, next) in r0.iter_mut().zip(deserialize_poly_vec(&share.h0, &ctx)?) {
            *acc += &next;
        }
        for (acc, next) in r1.iter_mut().zip(deserialize_poly_vec(&share.h1, &ctx)?) {
            *acc += &next;
        }
    }

    let mut c0 = r0;
    for (c0_poly, r1_poly) in c0.iter_mut().zip(r1.iter()) {
        *c0_poly += r1_poly;
        c0_poly.change_representation(Representation::NttShoup);
    }

    let mut c1 = deserialize_poly_vec(&req.round1_aggregate.h1, &ctx)?;
    for poly in &mut c1 {
        poly.change_representation(Representation::NttShoup);
    }

    let key = RelinearizationKey::new_from_ksk(new_level_zero_ksk(&params, c0, c1));
    let relinearization_key = key.to_bytes();
    Ok(AggregateDistributedRelinKeyResponse {
        relinearization_key: ArcBytes::from_bytes(&relinearization_key),
        audit: AggregatedDistributedRelinKeyAuditV1 {
            crs_binding_hash: req.round1_aggregate.audit.crs_binding_hash,
            relin_round1_aggregate_digest: req.round1_aggregate.audit.relin_round1_aggregate_digest,
            relinearization_key_digest: relin_key_digest(&relinearization_key),
        },
    })
}

pub fn verify_distributed_galois_key_audit(
    req: &AggregateDistributedGaloisKeyRequest,
    aggregated: &AggregateDistributedGaloisKeyResponse,
) -> Result<()> {
    let recomputed = aggregate_distributed_galois_key(req.clone())?;
    ensure!(
        recomputed.exponent == aggregated.exponent,
        "aggregated galois exponent mismatch"
    );
    ensure!(
        recomputed.galois_key == aggregated.galois_key,
        "aggregated galois key bytes mismatch"
    );
    ensure!(
        recomputed.audit == aggregated.audit,
        "aggregated galois audit mismatch"
    );
    Ok(())
}

pub fn verify_distributed_evaluation_key_audit(
    req: &AggregateDistributedEvaluationKeyRequest,
    aggregated: &AggregateDistributedEvaluationKeyResponse,
) -> Result<()> {
    let recomputed = aggregate_distributed_evaluation_key(req.clone())?;
    ensure!(
        recomputed.evaluation_key == aggregated.evaluation_key,
        "aggregated evaluation key bytes mismatch"
    );
    ensure!(
        recomputed.audit == aggregated.audit,
        "aggregated evaluation key audit mismatch"
    );
    Ok(())
}

pub fn verify_distributed_relin_round1_audit(
    req: &AggregateDistributedRelinRound1Request,
    aggregated: &AggregateDistributedRelinRound1Response,
) -> Result<()> {
    let recomputed = aggregate_distributed_relin_round1(req.clone())?;
    ensure!(
        recomputed.aggregate == aggregated.aggregate,
        "aggregated relin round1 mismatch"
    );
    Ok(())
}

pub fn verify_distributed_relin_key_audit(
    req: &AggregateDistributedRelinKeyRequest,
    aggregated: &AggregateDistributedRelinKeyResponse,
) -> Result<()> {
    let recomputed = aggregate_distributed_relin_key(req.clone())?;
    ensure!(
        recomputed.relinearization_key == aggregated.relinearization_key,
        "aggregated relinearization key bytes mismatch"
    );
    ensure!(
        recomputed.audit == aggregated.audit,
        "aggregated relinearization key audit mismatch"
    );
    Ok(())
}

fn validate_supported_galois_levels(
    ciphertext_level: u64,
    evaluation_key_level: u64,
) -> Result<()> {
    ensure!(
        ciphertext_level == SUPPORTED_LEVEL,
        "distributed galois generation currently supports ciphertext_level=0 only"
    );
    ensure!(
        evaluation_key_level == SUPPORTED_LEVEL,
        "distributed galois generation currently supports evaluation_key_level=0 only"
    );
    Ok(())
}

fn validate_supported_relin_levels(ciphertext_level: u64, key_level: u64) -> Result<()> {
    ensure!(
        ciphertext_level == SUPPORTED_LEVEL,
        "distributed relinearization currently supports ciphertext_level=0 only"
    );
    ensure!(
        key_level == SUPPORTED_LEVEL,
        "distributed relinearization currently supports key_level=0 only"
    );
    Ok(())
}

fn derive_galois_c1_poly(
    params: &Arc<BfvParameters>,
    root_seed: &EvalKeyRootSeed,
    exponent: usize,
    index: usize,
) -> Result<Poly> {
    let ctx = params.ctx_at_level(SUPPORTED_LEVEL as usize)?;
    Ok(Poly::random_from_seed(
        ctx,
        Representation::NttShoup,
        derive_seed(
            &root_seed.bytes,
            DOMAIN_GALOIS_C1,
            &[
                (exponent as u64).to_le_bytes(),
                (index as u64).to_le_bytes(),
            ],
        ),
    ))
}

fn derive_relin_crp_vector(
    params: &Arc<BfvParameters>,
    root_seed: &EvalKeyRootSeed,
) -> Result<Vec<CommonRandomPoly>> {
    let ctx = params.ctx_at_level(SUPPORTED_LEVEL as usize)?;
    (0..ctx.moduli().len())
        .map(|index| {
            CommonRandomPoly::new_deterministic(
                params,
                derive_seed(
                    &root_seed.bytes,
                    DOMAIN_RELIN_CRP,
                    &[(index as u64).to_le_bytes()],
                ),
            )
        })
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn derive_seed<const N: usize>(root: &[u8; 32], domain: &[u8], parts: &[[u8; N]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(root);
    hasher.update((domain.len() as u64).to_le_bytes());
    hasher.update(domain);
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn galois_crs_binding_hash(
    params: &Arc<BfvParameters>,
    root_seed: &EvalKeyRootSeed,
    exponent: u64,
    ciphertext_level: u64,
    evaluation_key_level: u64,
) -> Result<DistributedEvalKeyAuditHash> {
    let ctx = params.ctx_at_level(SUPPORTED_LEVEL as usize)?;
    let mut hasher = audit_hasher(DOMAIN_AUDIT_CRS_GALOIS_V1);
    audit_hash_u64(&mut hasher, exponent);
    audit_hash_u64(&mut hasher, ciphertext_level);
    audit_hash_u64(&mut hasher, evaluation_key_level);
    audit_hash_u64(&mut hasher, ctx.moduli().len() as u64);
    for index in 0..ctx.moduli().len() {
        audit_hash_bytes(
            &mut hasher,
            &derive_galois_c1_poly(params, root_seed, exponent as usize, index)?.to_bytes(),
        );
    }
    Ok(DistributedEvalKeyAuditHash::new(hasher.finalize().into()))
}

fn relin_crs_binding_hash(
    params: &Arc<BfvParameters>,
    root_seed: &EvalKeyRootSeed,
    ciphertext_level: u64,
    key_level: u64,
) -> Result<DistributedEvalKeyAuditHash> {
    let crp = derive_relin_crp_vector(params, root_seed)?;
    let mut hasher = audit_hasher(DOMAIN_AUDIT_CRS_RELIN_V1);
    audit_hash_u64(&mut hasher, ciphertext_level);
    audit_hash_u64(&mut hasher, key_level);
    audit_hash_u64(&mut hasher, crp.len() as u64);
    for poly in crp {
        audit_hash_bytes(&mut hasher, &poly.poly().to_bytes());
    }
    Ok(DistributedEvalKeyAuditHash::new(hasher.finalize().into()))
}

fn additive_share_commitment_hash(
    crs_binding_hash: DistributedEvalKeyAuditHash,
    secret_key_share: &[u8],
) -> DistributedEvalKeyAuditHash {
    let mut hasher = audit_hasher(DOMAIN_AUDIT_ADDITIVE_SHARE_COMMITMENT_V1);
    audit_hash_bytes(&mut hasher, &crs_binding_hash.bytes);
    audit_hash_bytes(&mut hasher, secret_key_share);
    DistributedEvalKeyAuditHash::new(hasher.finalize().into())
}

fn relin_ephemeral_u_commitment_hash(
    crs_binding_hash: DistributedEvalKeyAuditHash,
    ephemeral_u_share: &[u8],
) -> DistributedEvalKeyAuditHash {
    let mut hasher = audit_hasher(DOMAIN_AUDIT_RELIN_EPHEMERAL_COMMITMENT_V1);
    audit_hash_bytes(&mut hasher, &crs_binding_hash.bytes);
    audit_hash_bytes(&mut hasher, ephemeral_u_share);
    DistributedEvalKeyAuditHash::new(hasher.finalize().into())
}

fn galois_share_digest(
    exponent: u64,
    ciphertext_level: u64,
    evaluation_key_level: u64,
    c0_share: &[ArcBytes],
) -> DistributedEvalKeyAuditHash {
    let mut hasher = audit_hasher(DOMAIN_AUDIT_GALOIS_SHARE_DIGEST_V1);
    audit_hash_u64(&mut hasher, exponent);
    audit_hash_u64(&mut hasher, ciphertext_level);
    audit_hash_u64(&mut hasher, evaluation_key_level);
    audit_hash_arcbytes_vec(&mut hasher, c0_share);
    DistributedEvalKeyAuditHash::new(hasher.finalize().into())
}

fn relin_round1_share_digest(
    ciphertext_level: u64,
    key_level: u64,
    h0: &[ArcBytes],
    h1: &[ArcBytes],
) -> DistributedEvalKeyAuditHash {
    let mut hasher = audit_hasher(DOMAIN_AUDIT_RELIN_ROUND1_SHARE_DIGEST_V1);
    audit_hash_u64(&mut hasher, ciphertext_level);
    audit_hash_u64(&mut hasher, key_level);
    audit_hash_arcbytes_vec(&mut hasher, h0);
    audit_hash_arcbytes_vec(&mut hasher, h1);
    DistributedEvalKeyAuditHash::new(hasher.finalize().into())
}

fn relin_round1_aggregate_digest(
    ciphertext_level: u64,
    key_level: u64,
    h0: &[ArcBytes],
    h1: &[ArcBytes],
) -> DistributedEvalKeyAuditHash {
    let mut hasher = audit_hasher(DOMAIN_AUDIT_RELIN_ROUND1_AGGREGATE_DIGEST_V1);
    audit_hash_u64(&mut hasher, ciphertext_level);
    audit_hash_u64(&mut hasher, key_level);
    audit_hash_arcbytes_vec(&mut hasher, h0);
    audit_hash_arcbytes_vec(&mut hasher, h1);
    DistributedEvalKeyAuditHash::new(hasher.finalize().into())
}

fn relin_round2_share_digest(
    ciphertext_level: u64,
    key_level: u64,
    h0: &[ArcBytes],
    h1: &[ArcBytes],
) -> DistributedEvalKeyAuditHash {
    let mut hasher = audit_hasher(DOMAIN_AUDIT_RELIN_ROUND2_SHARE_DIGEST_V1);
    audit_hash_u64(&mut hasher, ciphertext_level);
    audit_hash_u64(&mut hasher, key_level);
    audit_hash_arcbytes_vec(&mut hasher, h0);
    audit_hash_arcbytes_vec(&mut hasher, h1);
    DistributedEvalKeyAuditHash::new(hasher.finalize().into())
}

fn galois_key_digest(exponent: u64, galois_key: &GaloisKeyProto) -> DistributedEvalKeyAuditHash {
    let mut hasher = audit_hasher(DOMAIN_AUDIT_GALOIS_KEY_DIGEST_V1);
    audit_hash_u64(&mut hasher, exponent);
    audit_hash_bytes(&mut hasher, &galois_key.encode_to_vec());
    DistributedEvalKeyAuditHash::new(hasher.finalize().into())
}

fn evaluation_key_digest(evaluation_key: &[u8]) -> DistributedEvalKeyAuditHash {
    let mut hasher = audit_hasher(DOMAIN_AUDIT_EVALUATION_KEY_DIGEST_V1);
    audit_hash_bytes(&mut hasher, evaluation_key);
    DistributedEvalKeyAuditHash::new(hasher.finalize().into())
}

fn relin_key_digest(relinearization_key: &[u8]) -> DistributedEvalKeyAuditHash {
    let mut hasher = audit_hasher(DOMAIN_AUDIT_RELIN_KEY_DIGEST_V1);
    audit_hash_bytes(&mut hasher, relinearization_key);
    DistributedEvalKeyAuditHash::new(hasher.finalize().into())
}

fn audit_hasher(domain: &[u8]) -> Sha256 {
    let mut hasher = Sha256::new();
    audit_hash_bytes(&mut hasher, domain);
    hasher
}

fn audit_hash_arcbytes_vec(hasher: &mut Sha256, bytes: &[ArcBytes]) {
    audit_hash_u64(hasher, bytes.len() as u64);
    for item in bytes {
        audit_hash_bytes(hasher, item);
    }
}

fn audit_hash_u64(hasher: &mut Sha256, value: u64) {
    hasher.update(value.to_le_bytes());
}

fn audit_hash_bytes(hasher: &mut Sha256, bytes: &[u8]) {
    audit_hash_u64(hasher, bytes.len() as u64);
    hasher.update(bytes);
}

fn deserialize_poly_vec(bytes: &[ArcBytes], ctx: &Arc<fhe_math::rq::Context>) -> Result<Vec<Poly>> {
    bytes
        .iter()
        .map(|bytes| Poly::from_bytes(bytes, ctx).map_err(Into::into))
        .collect()
}

fn serialize_poly_vec(polys: Vec<Poly>) -> Vec<ArcBytes> {
    polys
        .into_iter()
        .map(|poly| ArcBytes::from_bytes(&poly.to_bytes()))
        .collect()
}

fn decode_galois_key_proto(bytes: &[u8]) -> Result<GaloisKeyProto> {
    GaloisKeyProto::decode(bytes).context("invalid galois key bytes")
}

fn new_level_zero_ksk(
    params: &Arc<BfvParameters>,
    c0: Vec<Poly>,
    c1: Vec<Poly>,
) -> KeySwitchingKey {
    let ctx = params
        .ctx_at_level(SUPPORTED_LEVEL as usize)
        .expect("validated level-zero context")
        .clone();
    KeySwitchingKey {
        par: params.clone(),
        seed: None,
        c0: c0.into_boxed_slice(),
        c1: c1.into_boxed_slice(),
        ciphertext_level: SUPPORTED_LEVEL as usize,
        ctx_ciphertext: ctx.clone(),
        ksk_level: SUPPORTED_LEVEL as usize,
        ctx_ksk: ctx,
        log_base: 0,
    }
}

pub fn validate_serialized_galois_key(bytes: &[u8], params: &Arc<BfvParameters>) -> Result<()> {
    let proto = decode_galois_key_proto(bytes)?;
    EvaluationKey::try_convert_from(
        &EvaluationKeyProto {
            ciphertext_level: SUPPORTED_LEVEL as u32,
            evaluation_key_level: SUPPORTED_LEVEL as u32,
            gk: vec![proto],
        },
        params,
    )?;
    Ok(())
}

pub fn deserialize_evaluation_key(
    bytes: &[u8],
    params: &Arc<BfvParameters>,
) -> Result<EvaluationKey> {
    Ok(EvaluationKey::from_bytes(bytes, params)?)
}

pub fn deserialize_relinearization_key(
    bytes: &[u8],
    params: &Arc<BfvParameters>,
) -> Result<RelinearizationKey> {
    Ok(RelinearizationKey::from_bytes(bytes, params)?)
}

pub fn compute_galois_crs_binding_hash(
    params: &Arc<BfvParameters>,
    root_seed: &EvalKeyRootSeed,
    exponent: u64,
    ciphertext_level: u64,
    evaluation_key_level: u64,
) -> Result<[u8; 32]> {
    Ok(galois_crs_binding_hash(
        params,
        root_seed,
        exponent,
        ciphertext_level,
        evaluation_key_level,
    )?
    .bytes)
}

pub fn compute_relin_crs_binding_hash(
    params: &Arc<BfvParameters>,
    root_seed: &EvalKeyRootSeed,
    ciphertext_level: u64,
    key_level: u64,
) -> Result<[u8; 32]> {
    Ok(relin_crs_binding_hash(params, root_seed, ciphertext_level, key_level)?.bytes)
}

pub fn derive_relin_crp_component(
    params: &Arc<BfvParameters>,
    root_seed: &EvalKeyRootSeed,
    index: usize,
) -> Result<ArcBytes> {
    let crp = derive_relin_crp_vector(params, root_seed)?;
    let poly = crp
        .get(index)
        .ok_or_else(|| anyhow!("missing relin CRP component at index {index}"))?;
    Ok(ArcBytes::from_bytes(&poly.poly().to_bytes()))
}

pub fn compute_relin_garner_coefficient_decimal(
    params: &Arc<BfvParameters>,
    index: usize,
) -> Result<String> {
    let ctx = params.ctx_at_level(SUPPORTED_LEVEL as usize)?;
    let rns = RnsContext::new(&params.moduli()[..ctx.moduli().len()])?;
    let garner = rns
        .get_garner(index)
        .ok_or_else(|| anyhow!("missing Garner coefficient at index {index}"))?;
    Ok(garner.to_string())
}

pub fn serialize_secret_key_share(sk: &SecretKey) -> Result<ArcBytes> {
    Ok(ArcBytes::from_bytes(&crate::helpers::serialize_secret_key(
        sk,
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_fhe_params::encode_bfv_params;
    use fhe::bfv::BfvParametersBuilder;
    use rand::rngs::OsRng;

    fn test_params() -> Arc<BfvParameters> {
        BfvParametersBuilder::new()
            .set_degree(2048)
            .set_plaintext_modulus(12289)
            .set_moduli_sizes(&[62, 62, 62, 62, 62, 62])
            .build_arc()
            .expect("failed to build test BFV parameters")
    }

    fn test_config(params: &Arc<BfvParameters>) -> TrBFVConfig {
        TrBFVConfig::new(ArcBytes::from_bytes(&encode_bfv_params(params)), 3, 1)
    }

    fn test_root_seed() -> EvalKeyRootSeed {
        EvalKeyRootSeed::new([7u8; 32])
    }

    fn test_secret_key_shares(params: &Arc<BfvParameters>) -> Vec<ArcBytes> {
        let mut rng = OsRng;
        (0..3)
            .map(|_| {
                let sk = SecretKey::random(params, &mut rng);
                serialize_secret_key_share(&sk).expect("serialize secret key share")
            })
            .collect()
    }

    #[test]
    fn distributed_galois_audit_verification_passes_for_honest_transcript() {
        let params = test_params();
        let config = test_config(&params);
        let root_seed = test_root_seed();
        let secret_key_shares = test_secret_key_shares(&params);
        let exponent = 3u64;
        let mut rng = OsRng;

        let shares = secret_key_shares
            .iter()
            .map(|secret_key_share| {
                generate_distributed_galois_key_share(
                    &mut rng,
                    GenerateDistributedGaloisKeyShareRequest {
                        trbfv_config: config.clone(),
                        root_seed: root_seed.clone(),
                        secret_key_share: secret_key_share.clone(),
                        exponent,
                        ciphertext_level: 0,
                        evaluation_key_level: 0,
                    },
                )
                .expect("generate distributed galois share")
                .share
            })
            .collect::<Vec<_>>();

        let request = AggregateDistributedGaloisKeyRequest {
            trbfv_config: config,
            root_seed,
            exponent,
            ciphertext_level: 0,
            evaluation_key_level: 0,
            shares,
        };
        let aggregated = aggregate_distributed_galois_key(request.clone())
            .expect("aggregate distributed galois key");

        verify_distributed_galois_key_audit(&request, &aggregated)
            .expect("honest galois transcript should verify");
    }

    #[test]
    fn distributed_galois_audit_verification_fails_for_tampered_share_digest() {
        let params = test_params();
        let config = test_config(&params);
        let root_seed = test_root_seed();
        let secret_key_shares = test_secret_key_shares(&params);
        let exponent = 3u64;
        let mut rng = OsRng;

        let mut shares = secret_key_shares
            .iter()
            .map(|secret_key_share| {
                generate_distributed_galois_key_share(
                    &mut rng,
                    GenerateDistributedGaloisKeyShareRequest {
                        trbfv_config: config.clone(),
                        root_seed: root_seed.clone(),
                        secret_key_share: secret_key_share.clone(),
                        exponent,
                        ciphertext_level: 0,
                        evaluation_key_level: 0,
                    },
                )
                .expect("generate distributed galois share")
                .share
            })
            .collect::<Vec<_>>();
        shares[0].audit.galois_share_digest.bytes[0] ^= 0x01;

        let request = AggregateDistributedGaloisKeyRequest {
            trbfv_config: config,
            root_seed,
            exponent,
            ciphertext_level: 0,
            evaluation_key_level: 0,
            shares,
        };

        let err =
            aggregate_distributed_galois_key(request).expect_err("tampered share should fail");
        assert!(err
            .to_string()
            .contains("galois share audit digest mismatch"));
    }

    #[test]
    fn distributed_relin_key_audit_verification_fails_for_tampered_round2_linkage() {
        let params = test_params();
        let config = test_config(&params);
        let root_seed = test_root_seed();
        let secret_key_shares = test_secret_key_shares(&params);
        let mut rng = OsRng;

        let round1_outputs = secret_key_shares
            .iter()
            .map(|secret_key_share| {
                generate_distributed_relin_round1(
                    &mut rng,
                    GenerateDistributedRelinRound1Request {
                        trbfv_config: config.clone(),
                        root_seed: root_seed.clone(),
                        secret_key_share: secret_key_share.clone(),
                        ciphertext_level: 0,
                        key_level: 0,
                    },
                )
                .expect("generate distributed relin round1")
            })
            .collect::<Vec<_>>();

        let round1_request = AggregateDistributedRelinRound1Request {
            trbfv_config: config.clone(),
            ciphertext_level: 0,
            key_level: 0,
            shares: round1_outputs
                .iter()
                .map(|output| output.share.clone())
                .collect(),
        };
        let round1_aggregate = aggregate_distributed_relin_round1(round1_request)
            .expect("aggregate distributed relin round1")
            .aggregate;

        let mut round2_shares = secret_key_shares
            .iter()
            .zip(round1_outputs.iter())
            .map(|(secret_key_share, round1_output)| {
                generate_distributed_relin_round2(
                    &mut rng,
                    GenerateDistributedRelinRound2Request {
                        trbfv_config: config.clone(),
                        secret_key_share: secret_key_share.clone(),
                        helper: round1_output.helper.clone(),
                        round1_aggregate: round1_aggregate.clone(),
                    },
                )
                .expect("generate distributed relin round2")
                .share
            })
            .collect::<Vec<_>>();
        round2_shares[0].audit.round1_aggregate_digest.bytes[0] ^= 0x01;

        let request = AggregateDistributedRelinKeyRequest {
            trbfv_config: config,
            round1_aggregate,
            shares: round2_shares,
        };

        let err = aggregate_distributed_relin_key(request)
            .expect_err("tampered round2 linkage should fail");
        assert!(err
            .to_string()
            .contains("relin round2 share round1 aggregate linkage mismatch"));
    }

    #[test]
    fn distributed_evaluation_key_audit_verification_fails_for_tampered_final_bytes() {
        let params = test_params();
        let config = test_config(&params);
        let root_seed = test_root_seed();
        let secret_key_shares = test_secret_key_shares(&params);
        let exponent = 3u64;
        let mut rng = OsRng;

        let shares = secret_key_shares
            .iter()
            .map(|secret_key_share| {
                generate_distributed_galois_key_share(
                    &mut rng,
                    GenerateDistributedGaloisKeyShareRequest {
                        trbfv_config: config.clone(),
                        root_seed: root_seed.clone(),
                        secret_key_share: secret_key_share.clone(),
                        exponent,
                        ciphertext_level: 0,
                        evaluation_key_level: 0,
                    },
                )
                .expect("generate distributed galois share")
                .share
            })
            .collect::<Vec<_>>();

        let galois_key = aggregate_distributed_galois_key(AggregateDistributedGaloisKeyRequest {
            trbfv_config: config.clone(),
            root_seed,
            exponent,
            ciphertext_level: 0,
            evaluation_key_level: 0,
            shares,
        })
        .expect("aggregate distributed galois key")
        .galois_key;

        let request = AggregateDistributedEvaluationKeyRequest {
            trbfv_config: config,
            ciphertext_level: 0,
            evaluation_key_level: 0,
            galois_keys: vec![galois_key],
        };
        let aggregated = aggregate_distributed_evaluation_key(request.clone())
            .expect("aggregate distributed evaluation key");
        let mut tampered_bytes = aggregated.evaluation_key.extract_bytes();
        tampered_bytes[0] ^= 0x01;
        let aggregated = AggregateDistributedEvaluationKeyResponse {
            evaluation_key: ArcBytes::from_bytes(&tampered_bytes),
            ..aggregated
        };

        let err = verify_distributed_evaluation_key_audit(&request, &aggregated)
            .expect_err("tampered evaluation key bytes should fail verification");
        assert!(err
            .to_string()
            .contains("aggregated evaluation key bytes mismatch"));
    }
}
