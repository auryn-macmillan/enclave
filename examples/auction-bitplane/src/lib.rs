// SPDX-License-Identifier: LGPL-3.0-only

//! Threshold BFV helpers and a discrete-ladder Vickrey auction model.
//!
//! The auction semantics are now bucketed rather than exact-bit: each bidder
//! submits one ciphertext encoding cumulative willingness-to-pay over a public
//! price ladder plus a submission-order payload at their chosen bucket.
//! Authorized decryptions are public and progressive:
//! 1. decrypt a pair-indicator curve to find the second-price bucket,
//! 2. decrypt only the minimum extra bucket information needed to identify the
//!    winner under earliest-submission tie-breaks.

use e3_fhe_params::encode_bfv_params;
use e3_trbfv::{
    distributed_eval_key::{
        aggregate_distributed_evaluation_key, aggregate_distributed_galois_key,
        aggregate_distributed_relin_key, aggregate_distributed_relin_round1,
        deserialize_evaluation_key, deserialize_relinearization_key,
        generate_distributed_galois_key_share, generate_distributed_relin_round1,
        generate_distributed_relin_round2, serialize_secret_key_share,
        AggregateDistributedEvaluationKeyRequest, AggregateDistributedGaloisKeyRequest,
        AggregateDistributedRelinKeyRequest, AggregateDistributedRelinRound1Request,
        EvalKeyRootSeed, GenerateDistributedGaloisKeyShareRequest,
        GenerateDistributedRelinRound1Request, GenerateDistributedRelinRound2Request,
    },
    TrBFVConfig,
};
use e3_utils::ArcBytes;
use fhe::bfv::{
    BfvParameters, BfvParametersBuilder, Ciphertext, Encoding, EvaluationKey, Plaintext, PublicKey,
    RelinearizationKey, SecretKey,
};
use fhe::mbfv::{Aggregate, CommonRandomPoly, PublicKeyShare};
use fhe::trbfv::{ShareManager, TRBFV};
use fhe_math::rq::Poly;
use fhe_traits::{FheDecoder, FheEncoder, FheEncrypter};
use ndarray::Array2;
use num_bigint::BigInt;
use rand::rngs::OsRng;
use rand::RngCore;
use std::sync::Arc;

pub const BID_BITS: usize = 64;
pub const SLOTS: usize = 2048;
pub const COMMITTEE_N: usize = 3;
pub const THRESHOLD: usize = 1;
pub const SMUDGING_LAMBDA: usize = 80;
pub const PRICE_LEVELS: usize = 64;
pub const SLOT_WIDTH: usize = 16;

const CURVE_REGION_OFFSET: usize = 0;
const PAYLOAD_REGION_OFFSET: usize = PRICE_LEVELS * SLOT_WIDTH;
const MAX_SUBMISSION_ORDER_ENCODING: usize = (1 << SLOT_WIDTH) - 1;

pub fn build_params() -> Arc<BfvParameters> {
    BfvParametersBuilder::new()
        .set_degree(SLOTS)
        .set_plaintext_modulus(12289)
        .set_moduli_sizes(&[62, 62, 62, 62, 62, 62])
        .build_arc()
        .expect("failed to build BFV parameters")
}

pub fn generate_crp(params: &Arc<BfvParameters>) -> CommonRandomPoly {
    CommonRandomPoly::new(params, &mut OsRng).expect("CRP generation")
}

pub fn generate_eval_key_root_seed() -> EvalKeyRootSeed {
    let mut root_seed_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut root_seed_bytes);
    EvalKeyRootSeed::new(root_seed_bytes)
}

pub struct MemberKeygenOutput {
    pub sk: SecretKey,
    pub pk_share: PublicKeyShare,
    pub sk_shares: Vec<Array2<u64>>,
}

pub fn member_keygen(params: &Arc<BfvParameters>, crp: &CommonRandomPoly) -> MemberKeygenOutput {
    let sk = SecretKey::random(params, &mut OsRng);
    let pk_share =
        PublicKeyShare::new(&sk, crp.clone(), &mut OsRng).expect("public key share generation");

    let mut share_manager = ShareManager::new(COMMITTEE_N, THRESHOLD, params.clone());
    let sk_poly = share_manager
        .coeffs_to_poly_level0(sk.coeffs.clone().as_ref())
        .expect("sk → polynomial");
    let sk_shares = share_manager
        .generate_secret_shares_from_poly(sk_poly, OsRng)
        .expect("Shamir split");

    MemberKeygenOutput {
        sk,
        pk_share,
        sk_shares,
    }
}

pub fn aggregate_public_key(shares: Vec<PublicKeyShare>) -> PublicKey {
    PublicKey::from_shares(shares).expect("public key aggregation")
}

pub fn aggregate_sk_shares_for_party(
    all_members_shares: &[Vec<Array2<u64>>],
    party_idx: usize,
    params: &Arc<BfvParameters>,
) -> Poly {
    let share_manager = ShareManager::new(COMMITTEE_N, THRESHOLD, params.clone());

    let collected: Vec<Array2<u64>> = all_members_shares
        .iter()
        .map(|member_shares| {
            let mut party_slice = Array2::zeros((0, params.degree()));
            for modulus_matrix in member_shares.iter().take(params.moduli().len()) {
                party_slice
                    .push_row(ndarray::ArrayView::from(modulus_matrix.row(party_idx)))
                    .expect("row append");
            }
            party_slice
        })
        .collect();

    share_manager
        .aggregate_collected_shares(&collected)
        .expect("share aggregation")
}

pub fn build_eval_key_from_committee(
    member_sks: &[&SecretKey],
    params: &Arc<BfvParameters>,
    root_seed: &EvalKeyRootSeed,
) -> (EvaluationKey, RelinearizationKey) {
    let trbfv_config = TrBFVConfig::new(
        ArcBytes::from_bytes(&encode_bfv_params(params)),
        member_sks.len() as u64,
        THRESHOLD as u64,
    );

    let mut rng = OsRng;

    let modulus = (params.degree() * 2) as u64;
    let mut galois_exponents = Vec::new();
    let mut shift = 1usize;
    while shift < SLOTS / 2 {
        galois_exponents.push(mod_pow_u64(3, shift as u64, modulus));
        shift *= 2;
    }
    galois_exponents.push((params.degree() * 2 - 1) as u64);

    let secret_key_shares: Vec<_> = member_sks
        .iter()
        .map(|sk| serialize_secret_key_share(sk).expect("serialize secret key share"))
        .collect();

    let mut galois_keys = Vec::new();
    for exponent in galois_exponents {
        let shares = secret_key_shares
            .iter()
            .map(|secret_key_share| {
                generate_distributed_galois_key_share(
                    &mut rng,
                    GenerateDistributedGaloisKeyShareRequest {
                        trbfv_config: trbfv_config.clone(),
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
            .collect();

        let galois_key = aggregate_distributed_galois_key(AggregateDistributedGaloisKeyRequest {
            trbfv_config: trbfv_config.clone(),
            root_seed: root_seed.clone(),
            exponent,
            ciphertext_level: 0,
            evaluation_key_level: 0,
            shares,
        })
        .expect("aggregate distributed galois key")
        .galois_key;
        galois_keys.push(galois_key);
    }

    let eval_key = deserialize_evaluation_key(
        &aggregate_distributed_evaluation_key(AggregateDistributedEvaluationKeyRequest {
            trbfv_config: trbfv_config.clone(),
            ciphertext_level: 0,
            evaluation_key_level: 0,
            galois_keys,
        })
        .expect("aggregate distributed evaluation key")
        .evaluation_key,
        params,
    )
    .expect("deserialize evaluation key");

    let round1_outputs: Vec<_> = secret_key_shares
        .iter()
        .map(|secret_key_share| {
            generate_distributed_relin_round1(
                &mut rng,
                GenerateDistributedRelinRound1Request {
                    trbfv_config: trbfv_config.clone(),
                    root_seed: root_seed.clone(),
                    secret_key_share: secret_key_share.clone(),
                    ciphertext_level: 0,
                    key_level: 0,
                },
            )
            .expect("generate distributed relin round1")
        })
        .collect::<Vec<_>>();

    let round1_aggregate =
        aggregate_distributed_relin_round1(AggregateDistributedRelinRound1Request {
            trbfv_config: trbfv_config.clone(),
            ciphertext_level: 0,
            key_level: 0,
            shares: round1_outputs
                .iter()
                .map(|output| output.share.clone())
                .collect(),
        })
        .expect("aggregate distributed relin round1")
        .aggregate;

    let round2_shares = secret_key_shares
        .iter()
        .zip(round1_outputs.iter())
        .map(|(secret_key_share, round1_output)| {
            generate_distributed_relin_round2(
                &mut rng,
                GenerateDistributedRelinRound2Request {
                    trbfv_config: trbfv_config.clone(),
                    secret_key_share: secret_key_share.clone(),
                    helper: round1_output.helper.clone(),
                    round1_aggregate: round1_aggregate.clone(),
                },
            )
            .expect("generate distributed relin round2")
            .share
        })
        .collect();

    let relin_key = deserialize_relinearization_key(
        &aggregate_distributed_relin_key(AggregateDistributedRelinKeyRequest {
            trbfv_config,
            round1_aggregate,
            shares: round2_shares,
        })
        .expect("aggregate distributed relin key")
        .relinearization_key,
        params,
    )
    .expect("deserialize relin key");

    (eval_key, relin_key)
}

fn mod_pow_u64(base: u64, exponent: u64, modulus: u64) -> u64 {
    let mut result = 1u128;
    let mut base_acc = (base % modulus) as u128;
    let modulus = modulus as u128;
    let mut exp = exponent;
    while exp > 0 {
        if exp & 1 == 1 {
            result = (result * base_acc) % modulus;
        }
        base_acc = (base_acc * base_acc) % modulus;
        exp >>= 1;
    }
    result as u64
}

pub fn generate_smudging_noise(params: &Arc<BfvParameters>, num_ciphertexts: usize) -> Vec<BigInt> {
    let trbfv = TRBFV::new(COMMITTEE_N, THRESHOLD, params.clone()).expect("TRBFV config");
    trbfv
        .generate_smudging_error(num_ciphertexts, SMUDGING_LAMBDA, &mut OsRng)
        .expect("smudging noise generation")
}

pub fn compute_decryption_shares(
    ciphertexts: &[Ciphertext],
    sk_poly_sum: &Poly,
    smudging_coeffs: &[BigInt],
    params: &Arc<BfvParameters>,
) -> Vec<Poly> {
    let share_manager = ShareManager::new(COMMITTEE_N, THRESHOLD, params.clone());
    let es_poly = share_manager
        .bigints_to_poly(smudging_coeffs)
        .expect("smudging noise → polynomial");

    ciphertexts
        .iter()
        .map(|ct| {
            share_manager
                .decryption_share(
                    Arc::new(ct.clone()),
                    sk_poly_sum.clone(),
                    (*es_poly).clone(),
                )
                .expect("decryption share")
        })
        .collect()
}

pub fn threshold_decrypt(
    party_shares: &[(usize, Vec<Poly>)],
    ciphertexts: &[Ciphertext],
    params: &Arc<BfvParameters>,
) -> Vec<Plaintext> {
    let share_manager = ShareManager::new(COMMITTEE_N, THRESHOLD, params.clone());
    let reconstructing_parties: Vec<usize> = party_shares.iter().map(|(id, _)| *id).collect();

    (0..ciphertexts.len())
        .map(|ct_idx| {
            let d_shares: Vec<Poly> = party_shares
                .iter()
                .map(|(_, shares)| shares[ct_idx].clone())
                .collect();
            share_manager
                .decrypt_from_shares(
                    d_shares,
                    reconstructing_parties.clone(),
                    Arc::new(ciphertexts[ct_idx].clone()),
                )
                .expect("threshold decryption")
        })
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TopBucketSignal {
    pub occupied: bool,
    pub submission_order: Option<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VickreyOutcome {
    pub winner_bidder: usize,
    pub second_price_bucket: Option<usize>,
    pub second_price: Option<u64>,
    pub winner_revelation_bucket: Option<usize>,
    pub top_tie: bool,
}

fn assert_ladder_layout(params: &Arc<BfvParameters>) {
    assert!(
        PAYLOAD_REGION_OFFSET + PRICE_LEVELS * SLOT_WIDTH <= params.degree(),
        "ladder layout exceeds polynomial degree"
    );
}

fn assert_ladder(price_ladder: &[u64]) {
    assert!(!price_ladder.is_empty(), "price ladder cannot be empty");
    assert!(
        price_ladder.len() <= PRICE_LEVELS,
        "price ladder exceeds PRICE_LEVELS={PRICE_LEVELS}"
    );
    assert!(
        price_ladder.windows(2).all(|pair| pair[0] < pair[1]),
        "price ladder must be strictly increasing"
    );
}

fn curve_block_offset(level_idx: usize) -> usize {
    CURVE_REGION_OFFSET + level_idx * SLOT_WIDTH
}

fn payload_block_offset(level_idx: usize) -> usize {
    PAYLOAD_REGION_OFFSET + level_idx * SLOT_WIDTH
}

fn encode_value_into_block(slots: &mut [u64], block_offset: usize, value: u64) {
    for bit in 0..SLOT_WIDTH {
        slots[block_offset + bit] = (value >> bit) & 1;
    }
}

fn decode_slot(raw: u64, plaintext_modulus: u64) -> u64 {
    if raw > plaintext_modulus / 2 {
        0
    } else {
        raw
    }
}

fn decode_block_value(slots: &[u64], block_offset: usize, plaintext_modulus: u64) -> u64 {
    (0..SLOT_WIDTH)
        .map(|bit| decode_slot(slots[block_offset + bit], plaintext_modulus) * (1u64 << bit))
        .sum()
}

fn price_to_level_index(price: u64, price_ladder: &[u64]) -> usize {
    price_ladder
        .binary_search(&price)
        .expect("bid price must exist on the public ladder")
}

pub fn build_price_ladder(min_price: u64, max_price: u64, levels: usize) -> Vec<u64> {
    assert!(levels >= 2, "price ladder requires at least 2 levels");
    assert!(
        levels <= PRICE_LEVELS,
        "levels exceed PRICE_LEVELS={PRICE_LEVELS}"
    );
    assert!(
        min_price < max_price,
        "price ladder requires min_price < max_price"
    );

    let span = max_price - min_price;
    let denominator = (levels - 1) as u64;

    (0..levels)
        .map(|idx| min_price + (span * idx as u64) / denominator)
        .collect()
}

pub fn encode_bid(
    price: u64,
    submission_order: usize,
    price_ladder: &[u64],
    params: &Arc<BfvParameters>,
) -> Plaintext {
    assert_ladder_layout(params);
    assert_ladder(price_ladder);
    assert!(
        submission_order < MAX_SUBMISSION_ORDER_ENCODING,
        "submission order exceeds payload capacity"
    );

    let level_idx = price_to_level_index(price, price_ladder);
    let mut slots = vec![0u64; params.degree()];

    for occupied_level in 0..=level_idx {
        encode_value_into_block(&mut slots, curve_block_offset(occupied_level), 1);
    }
    encode_value_into_block(
        &mut slots,
        payload_block_offset(level_idx),
        (submission_order + 1) as u64,
    );

    Plaintext::try_encode(&slots, Encoding::simd(), params).expect("encode ladder bid")
}

pub fn encrypt_bid(pt: &Plaintext, pk: &PublicKey) -> Ciphertext {
    pk.try_encrypt(pt, &mut OsRng).expect("encrypt ladder bid")
}

pub fn accumulate_bid(global: &mut Ciphertext, contribution: &Ciphertext) {
    *global = &*global + contribution;
}

pub fn build_top_bucket_mask(level_idx: usize, params: &Arc<BfvParameters>) -> Plaintext {
    assert_ladder_layout(params);
    assert!(level_idx < PRICE_LEVELS, "top-bucket index out of range");

    let mut slots = vec![0u64; params.degree()];
    for bit in 0..SLOT_WIDTH {
        slots[curve_block_offset(level_idx) + bit] = 1;
        slots[payload_block_offset(level_idx) + bit] = 1;
    }

    Plaintext::try_encode(&slots, Encoding::simd(), params).expect("encode top-bucket mask")
}

pub fn build_curve_bucket_mask(level_idx: usize, params: &Arc<BfvParameters>) -> Plaintext {
    assert_ladder_layout(params);
    assert!(level_idx < PRICE_LEVELS, "curve bucket index out of range");

    let mut slots = vec![0u64; params.degree()];
    slots[curve_block_offset(level_idx)] = 1;

    Plaintext::try_encode(&slots, Encoding::simd(), params).expect("encode curve bucket mask")
}

pub fn mask_top_bucket(target: &Ciphertext, mask: &Plaintext) -> Ciphertext {
    target * mask
}

pub fn compute_pair_curve(
    aggregate_curve: &Ciphertext,
    num_levels: usize,
    relin_key: &RelinearizationKey,
    params: &Arc<BfvParameters>,
) -> Ciphertext {
    assert_ladder_layout(params);
    assert!(
        num_levels <= PRICE_LEVELS,
        "num_levels exceeds PRICE_LEVELS"
    );

    let mut mask_slots = vec![0u64; params.degree()];
    let mut one_slots = vec![0u64; params.degree()];
    for level_idx in 0..num_levels {
        let slot = curve_block_offset(level_idx);
        mask_slots[slot] = 1;
        one_slots[slot] = 1;
    }

    let mask =
        Plaintext::try_encode(&mask_slots, Encoding::simd(), params).expect("encode pair mask");
    let ones = Plaintext::try_encode(&one_slots, Encoding::simd(), params).expect("encode ones");

    let masked = aggregate_curve * &mask;
    let shifted = &masked - &ones;
    let mut pair_curve = &masked * &shifted;
    relin_key
        .relinearizes(&mut pair_curve)
        .expect("relinearize pair curve");
    pair_curve
}

pub fn decode_aggregate_curve(
    slots: &[u64],
    num_levels: usize,
    plaintext_modulus: u64,
) -> Vec<u64> {
    assert!(
        num_levels <= PRICE_LEVELS,
        "num_levels exceeds PRICE_LEVELS"
    );
    (0..num_levels)
        .map(|level_idx| {
            decode_block_value(slots, curve_block_offset(level_idx), plaintext_modulus)
        })
        .collect()
}

pub fn decode_aggregate_curve_plaintext(
    pt: &Plaintext,
    num_levels: usize,
    params: &Arc<BfvParameters>,
) -> Vec<u64> {
    let slots = Vec::<u64>::try_decode(pt, Encoding::simd()).expect("decode aggregate curve");
    decode_aggregate_curve(&slots, num_levels, params.plaintext())
}

pub fn decode_curve_bucket_plaintext(
    pt: &Plaintext,
    level_idx: usize,
    params: &Arc<BfvParameters>,
) -> u64 {
    let slots = Vec::<u64>::try_decode(pt, Encoding::simd()).expect("decode curve bucket");
    decode_slot(slots[curve_block_offset(level_idx)], params.plaintext())
}

pub fn decode_curve_bucket_presence_plaintext(
    pt: &Plaintext,
    level_idx: usize,
    params: &Arc<BfvParameters>,
) -> bool {
    decode_curve_bucket_plaintext(pt, level_idx, params) > 0
}

fn find_highest_bucket_progressively<F>(
    num_levels: usize,
    lower_bound_inclusive: usize,
    mut decrypt_bucket_presence: F,
) -> Option<usize>
where
    F: FnMut(usize) -> bool,
{
    assert!(
        lower_bound_inclusive <= num_levels,
        "lower bound exceeds number of levels"
    );

    (lower_bound_inclusive..num_levels)
        .rev()
        .find(|&level_idx| decrypt_bucket_presence(level_idx))
}

pub fn find_second_price_bucket_progressive<F>(
    price_ladder: &[u64],
    decrypt_pair_bucket_presence: F,
) -> Option<(usize, u64)>
where
    F: FnMut(usize) -> bool,
{
    assert_ladder(price_ladder);

    find_highest_bucket_progressively(price_ladder.len(), 0, decrypt_pair_bucket_presence)
        .map(|idx| (idx, price_ladder[idx]))
}

pub fn find_top_bucket_progressive<F>(
    price_ladder: &[u64],
    second_price_bucket: Option<usize>,
    decrypt_curve_bucket_presence: F,
) -> Option<(usize, u64)>
where
    F: FnMut(usize) -> bool,
{
    assert_ladder(price_ladder);

    if let Some(level_idx) = second_price_bucket {
        assert!(
            level_idx < price_ladder.len(),
            "second-price bucket out of range"
        );
    }

    let lower_bound = second_price_bucket.map_or(0, |level_idx| level_idx.saturating_add(1));
    find_highest_bucket_progressively(
        price_ladder.len(),
        lower_bound,
        decrypt_curve_bucket_presence,
    )
    .or_else(|| second_price_bucket)
    .map(|idx| (idx, price_ladder[idx]))
}

pub fn find_top_bucket(aggregate_curve: &[u64], price_ladder: &[u64]) -> Option<(usize, u64)> {
    assert_eq!(
        aggregate_curve.len(),
        price_ladder.len(),
        "aggregate curve / ladder length mismatch"
    );

    (0..aggregate_curve.len())
        .rev()
        .find(|&idx| aggregate_curve[idx] > 0)
        .map(|idx| (idx, price_ladder[idx]))
}

pub fn find_second_price_bucket(
    aggregate_curve: &[u64],
    price_ladder: &[u64],
) -> Option<(usize, u64)> {
    assert_eq!(
        aggregate_curve.len(),
        price_ladder.len(),
        "aggregate curve / ladder length mismatch"
    );

    if aggregate_curve.first().copied().unwrap_or(0) <= 1 {
        return None;
    }

    (0..aggregate_curve.len())
        .rev()
        .find(|&idx| aggregate_curve[idx] >= 2)
        .map(|idx| (idx, price_ladder[idx]))
}

pub fn decode_top_bucket_signal(
    pt: &Plaintext,
    level_idx: usize,
    params: &Arc<BfvParameters>,
) -> TopBucketSignal {
    assert!(level_idx < PRICE_LEVELS, "top-bucket index out of range");

    let slots = Vec::<u64>::try_decode(pt, Encoding::simd()).expect("decode top-bucket signal");
    let occupied =
        decode_block_value(&slots, curve_block_offset(level_idx), params.plaintext()) > 0;
    let encoded_order =
        decode_block_value(&slots, payload_block_offset(level_idx), params.plaintext());

    TopBucketSignal {
        occupied,
        submission_order: if encoded_order == 0 {
            None
        } else {
            Some((encoded_order - 1) as usize)
        },
    }
}

pub fn identify_top_bucket_winner(signals: &[TopBucketSignal]) -> Option<usize> {
    signals
        .iter()
        .enumerate()
        .filter_map(|(bidder_idx, signal)| {
            signal
                .submission_order
                .filter(|_| signal.occupied)
                .map(|submission_order| (bidder_idx, submission_order))
        })
        .min_by_key(|&(bidder_idx, submission_order)| (submission_order, bidder_idx))
        .map(|(bidder_idx, _)| bidder_idx)
}

pub fn identify_unique_bucket_winner(bucket_presence: &[bool]) -> Option<usize> {
    let mut occupied = bucket_presence
        .iter()
        .enumerate()
        .filter_map(|(bidder_idx, &present)| present.then_some(bidder_idx));
    let winner = occupied.next()?;
    if occupied.next().is_some() {
        None
    } else {
        Some(winner)
    }
}

pub fn resolve_progressive_vickrey_outcome(
    winner_bidder: usize,
    price_ladder: &[u64],
    second_price_bucket: Option<usize>,
    reveal_level: usize,
) -> Option<VickreyOutcome> {
    assert_ladder(price_ladder);

    if reveal_level >= price_ladder.len() {
        return None;
    }

    let second_price = match second_price_bucket {
        Some(level_idx) => {
            if level_idx >= price_ladder.len() {
                return None;
            }
            Some(price_ladder[level_idx])
        }
        None => None,
    };

    Some(VickreyOutcome {
        winner_bidder,
        second_price_bucket,
        second_price,
        winner_revelation_bucket: Some(reveal_level),
        top_tie: second_price_bucket == Some(reveal_level),
    })
}

pub fn resolve_vickrey_outcome(
    aggregate_curve: &[u64],
    price_ladder: &[u64],
    reveal_level: usize,
    top_bucket_signals: &[TopBucketSignal],
) -> Option<VickreyOutcome> {
    let winner_bidder = identify_top_bucket_winner(top_bucket_signals)?;
    let second = find_second_price_bucket(aggregate_curve, price_ladder);
    resolve_progressive_vickrey_outcome(
        winner_bidder,
        price_ladder,
        second.map(|(idx, _)| idx),
        reveal_level,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_slots(pt: &Plaintext) -> Vec<u64> {
        Vec::<u64>::try_decode(pt, Encoding::simd()).expect("decode slots")
    }

    fn aggregate_slots(pts: &[Plaintext]) -> Vec<u64> {
        let decoded: Vec<Vec<u64>> = pts.iter().map(decode_slots).collect();
        let mut sum = vec![0u64; decoded.first().map_or(0, Vec::len)];
        for row in decoded {
            for (slot, value) in sum.iter_mut().zip(row) {
                *slot += value;
            }
        }
        sum
    }

    fn setup_committee(
        params: &Arc<BfvParameters>,
    ) -> (PublicKey, Vec<Poly>, Vec<MemberKeygenOutput>) {
        let crp = generate_crp(params);
        let members: Vec<_> = (0..COMMITTEE_N)
            .map(|_| member_keygen(params, &crp))
            .collect();

        let joint_pk = aggregate_public_key(members.iter().map(|m| m.pk_share.clone()).collect());
        let all_sk_shares: Vec<_> = members.iter().map(|m| m.sk_shares.clone()).collect();
        let sk_poly_sums: Vec<_> = (0..COMMITTEE_N)
            .map(|i| aggregate_sk_shares_for_party(&all_sk_shares, i, params))
            .collect();

        (joint_pk, sk_poly_sums, members)
    }

    #[test]
    fn unique_top_bidder_uses_progressive_bucket_reveals() {
        let params = build_params();
        let ladder = vec![100, 200, 300, 400];
        let bids = vec![
            encode_bid(200, 0, &ladder, &params),
            encode_bid(400, 1, &ladder, &params),
            encode_bid(300, 2, &ladder, &params),
        ];

        let aggregate = aggregate_slots(&bids);
        let curve = decode_aggregate_curve(&aggregate, ladder.len(), params.plaintext());
        let pair_curve: Vec<u64> = curve
            .iter()
            .map(|count| count.saturating_mul(count.saturating_sub(1)))
            .collect();
        let mut pair_bucket_queries = Vec::new();
        let second = find_second_price_bucket_progressive(&ladder, |level_idx| {
            pair_bucket_queries.push(level_idx);
            pair_curve[level_idx] > 0
        });
        let mut top_bucket_queries = Vec::new();
        let top = find_top_bucket_progressive(&ladder, second.map(|(idx, _)| idx), |level_idx| {
            top_bucket_queries.push(level_idx);
            curve[level_idx] > 0
        });
        let top_bucket = top.map(|(idx, _)| idx).expect("top bucket");
        let presence: Vec<bool> = bids
            .iter()
            .map(|bid| decode_curve_bucket_presence_plaintext(bid, top_bucket, &params))
            .collect();
        let winner = identify_unique_bucket_winner(&presence).expect("unique winner");

        assert_eq!(curve, vec![3, 3, 2, 1]);
        assert_eq!(pair_bucket_queries, vec![3, 2]);
        assert_eq!(top_bucket_queries, vec![3]);
        assert_eq!(top, Some((3, 400)));
        assert_eq!(second, Some((2, 300)));
        assert_eq!(presence, vec![false, true, false]);
        assert_eq!(winner, 1);

        let outcome =
            resolve_progressive_vickrey_outcome(winner, &ladder, Some(2), 3).expect("outcome");
        assert_eq!(outcome.winner_bidder, 1);
        assert_eq!(outcome.second_price_bucket, Some(2));
        assert_eq!(outcome.second_price, Some(300));
        assert_eq!(outcome.winner_revelation_bucket, Some(3));
        assert_eq!(outcome.top_tie, false);
    }

    #[test]
    fn tie_at_top_only_reveals_pair_bucket_then_tie_break_signals() {
        let params = build_params();
        let ladder = vec![100, 200, 300, 400];
        let bids = vec![
            encode_bid(400, 2, &ladder, &params),
            encode_bid(400, 0, &ladder, &params),
            encode_bid(300, 1, &ladder, &params),
        ];

        let aggregate = aggregate_slots(&bids);
        let curve = decode_aggregate_curve(&aggregate, ladder.len(), params.plaintext());
        let pair_curve: Vec<u64> = curve
            .iter()
            .map(|count| count.saturating_mul(count.saturating_sub(1)))
            .collect();
        let mut pair_bucket_queries = Vec::new();
        let second = find_second_price_bucket_progressive(&ladder, |level_idx| {
            pair_bucket_queries.push(level_idx);
            pair_curve[level_idx] > 0
        });
        let mut top_bucket_queries = Vec::new();
        let top = find_top_bucket_progressive(&ladder, second.map(|(idx, _)| idx), |level_idx| {
            top_bucket_queries.push(level_idx);
            curve[level_idx] > 0
        });
        let signals = vec![
            decode_top_bucket_signal(&bids[0], 3, &params),
            decode_top_bucket_signal(&bids[1], 3, &params),
            decode_top_bucket_signal(&bids[2], 3, &params),
        ];

        assert_eq!(curve, vec![3, 3, 3, 2]);
        assert_eq!(pair_bucket_queries, vec![3]);
        assert!(top_bucket_queries.is_empty());
        assert_eq!(top, Some((3, 400)));
        assert_eq!(second, Some((3, 400)));
        assert_eq!(identify_top_bucket_winner(&signals), Some(1));

        let outcome = resolve_progressive_vickrey_outcome(1, &ladder, Some(3), 3).expect("outcome");
        assert_eq!(outcome.second_price_bucket, Some(3));
        assert_eq!(outcome.second_price, Some(400));
        assert_eq!(outcome.top_tie, true);
    }

    #[test]
    fn single_bidder_progressively_searches_pair_then_curve() {
        let params = build_params();
        let ladder = vec![100, 200, 300, 400];
        let bid = encode_bid(300, 0, &ladder, &params);
        let curve = decode_aggregate_curve(&decode_slots(&bid), ladder.len(), params.plaintext());
        let pair_curve: Vec<u64> = curve
            .iter()
            .map(|count| count.saturating_mul(count.saturating_sub(1)))
            .collect();
        let mut pair_bucket_queries = Vec::new();
        let second = find_second_price_bucket_progressive(&ladder, |level_idx| {
            pair_bucket_queries.push(level_idx);
            pair_curve[level_idx] > 0
        });
        let mut top_bucket_queries = Vec::new();
        let top = find_top_bucket_progressive(&ladder, None, |level_idx| {
            top_bucket_queries.push(level_idx);
            curve[level_idx] > 0
        });
        let top_bucket = top.map(|(idx, _)| idx).expect("top bucket");
        let presence = [decode_curve_bucket_presence_plaintext(
            &bid, top_bucket, &params,
        )];

        assert_eq!(curve, vec![1, 1, 1, 0]);
        assert_eq!(pair_bucket_queries, vec![3, 2, 1, 0]);
        assert_eq!(top_bucket_queries, vec![3, 2]);
        assert_eq!(top, Some((2, 300)));
        assert_eq!(second, None);
        assert_eq!(identify_unique_bucket_winner(&presence), Some(0));
    }

    #[test]
    fn progressive_pair_bucket_decryption_stops_at_second_price_bucket() {
        let params = build_params();
        let ladder = vec![100, 200, 300, 400];
        let (joint_pk, sk_poly_sums, members) = setup_committee(&params);
        let eval_key_root_seed = generate_eval_key_root_seed();
        let member_sk_refs: Vec<&_> = members.iter().map(|m| &m.sk).collect();
        let (_eval_key, relin_key) =
            build_eval_key_from_committee(&member_sk_refs, &params, &eval_key_root_seed);

        let bidder_pts = vec![
            encode_bid(200, 0, &ladder, &params),
            encode_bid(400, 1, &ladder, &params),
            encode_bid(300, 2, &ladder, &params),
        ];
        let bidder_cts: Vec<_> = bidder_pts
            .iter()
            .map(|pt| encrypt_bid(pt, &joint_pk))
            .collect();
        let mut aggregate = bidder_cts[0].clone();
        for ct in bidder_cts.iter().skip(1) {
            accumulate_bid(&mut aggregate, ct);
        }

        let pair_curve = compute_pair_curve(&aggregate, ladder.len(), &relin_key, &params);
        let participating = [0usize, 1usize];

        let mut decrypted_levels = Vec::new();
        let second = find_second_price_bucket_progressive(&ladder, |level_idx| {
            decrypted_levels.push(level_idx);
            let mask = build_curve_bucket_mask(level_idx, &params);
            let masked = vec![&pair_curve * &mask];
            let shares: Vec<(usize, Vec<_>)> = participating
                .iter()
                .map(|&i| {
                    let smudging = generate_smudging_noise(&params, 1);
                    let decryption_shares =
                        compute_decryption_shares(&masked, &sk_poly_sums[i], &smudging, &params);
                    (i + 1, decryption_shares)
                })
                .collect();
            let pt = threshold_decrypt(&shares, &masked, &params)
                .into_iter()
                .next()
                .expect("pair bucket plaintext");
            decode_curve_bucket_presence_plaintext(&pt, level_idx, &params)
        });

        assert_eq!(decrypted_levels, vec![3, 2]);
        assert_eq!(second, Some((2, 300)));
    }

    #[test]
    fn pair_curve_marks_only_buckets_with_at_least_two_bidders_when_individually_decrypted() {
        let params = build_params();
        let ladder = vec![100, 200, 300, 400];
        let (joint_pk, sk_poly_sums, members) = setup_committee(&params);
        let eval_key_root_seed = generate_eval_key_root_seed();
        let member_sk_refs: Vec<&_> = members.iter().map(|m| &m.sk).collect();
        let (_eval_key, relin_key) =
            build_eval_key_from_committee(&member_sk_refs, &params, &eval_key_root_seed);

        let bidder_pts = vec![
            encode_bid(200, 0, &ladder, &params),
            encode_bid(400, 1, &ladder, &params),
            encode_bid(300, 2, &ladder, &params),
        ];
        let bidder_cts: Vec<_> = bidder_pts
            .iter()
            .map(|pt| encrypt_bid(pt, &joint_pk))
            .collect();
        let mut aggregate = bidder_cts[0].clone();
        for ct in bidder_cts.iter().skip(1) {
            accumulate_bid(&mut aggregate, ct);
        }

        let pair_curve = compute_pair_curve(&aggregate, ladder.len(), &relin_key, &params);
        let participating = [0usize, 1usize];

        let pair_bucket_pts: Vec<_> = (0..ladder.len())
            .map(|level_idx| {
                let mask = build_curve_bucket_mask(level_idx, &params);
                let masked = vec![&pair_curve * &mask];
                let shares: Vec<(usize, Vec<_>)> = participating
                    .iter()
                    .map(|&i| {
                        let smudging = generate_smudging_noise(&params, 1);
                        let decryption_shares = compute_decryption_shares(
                            &masked,
                            &sk_poly_sums[i],
                            &smudging,
                            &params,
                        );
                        (i + 1, decryption_shares)
                    })
                    .collect();
                threshold_decrypt(&shares, &masked, &params)
                    .into_iter()
                    .next()
                    .expect("pair bucket plaintext")
            })
            .collect();

        let pair_values: Vec<u64> = pair_bucket_pts
            .iter()
            .enumerate()
            .map(|(level_idx, pt)| decode_curve_bucket_plaintext(pt, level_idx, &params))
            .collect();

        assert_eq!(pair_values[0] > 0, true);
        assert_eq!(pair_values[1] > 0, true);
        assert_eq!(pair_values[2] > 0, true);
        assert_eq!(pair_values[3], 0);
    }

    #[test]
    fn masked_top_bucket_extraction_only_reveals_top_bucket_signal() {
        let params = build_params();
        let ladder = vec![100, 200, 300, 400];
        let (joint_pk, sk_poly_sums, _members) = setup_committee(&params);

        let winning_pt = encode_bid(400, 0, &ladder, &params);
        let losing_pt = encode_bid(300, 1, &ladder, &params);
        let winning_ct = encrypt_bid(&winning_pt, &joint_pk);
        let losing_ct = encrypt_bid(&losing_pt, &joint_pk);
        let mask = build_top_bucket_mask(3, &params);
        let masked = vec![
            mask_top_bucket(&winning_ct, &mask),
            mask_top_bucket(&losing_ct, &mask),
        ];

        let participating = [0usize, 1usize];
        let party_shares: Vec<(usize, Vec<_>)> = participating
            .iter()
            .map(|&i| {
                let smudging = generate_smudging_noise(&params, masked.len());
                let shares =
                    compute_decryption_shares(&masked, &sk_poly_sums[i], &smudging, &params);
                (i + 1, shares)
            })
            .collect();

        let plaintexts = threshold_decrypt(&party_shares, &masked, &params);
        let winning_signal = decode_top_bucket_signal(&plaintexts[0], 3, &params);
        let losing_signal = decode_top_bucket_signal(&plaintexts[1], 3, &params);

        assert_eq!(winning_signal.occupied, true);
        assert_eq!(winning_signal.submission_order, Some(0));
        assert_eq!(losing_signal.occupied, false);
        assert_eq!(losing_signal.submission_order, None);
    }
}
