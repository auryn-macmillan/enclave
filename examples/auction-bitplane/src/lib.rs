// SPDX-License-Identifier: LGPL-3.0-only
//
//! # Bit-Plane Auction — Threshold FHE Library
//!
//! A sealed-bid **Vickrey (second-price)** auction built on threshold BFV
//! fully-homomorphic encryption with SIMD batching.
//!
//! ## Committee & Key Generation
//!
//! A **2-of-3 committee** jointly generates the encryption key using a
//! distributed key generation (DKG) protocol — no trusted dealer.  Each
//! member generates a secret key share, derives a public key share, and
//! Shamir-splits their secret for threshold decryption later.  The public
//! key shares are aggregated into a single joint public key that bidders
//! encrypt to.
//!
//! ## Encoding
//!
//! Each bidder is assigned a SIMD **slot** (one per ring position).  A bid
//! of `B` bits is decomposed into `B` *bitplane* ciphertexts — one per bit
//! position, MSB first.  Slot `i` of bitplane `j` holds bit `j` of bidder
//! `i`'s bid.
//!
//! ## Tally (FHE Phase — Multiplicative Depth 1)
//!
//! For each bitplane `j` we compute:
//!
//! ```text
//!   masked_j    = bitplane[j] × slot_mask       // zero unused SIMD slots
//!   ones_j      = Σ_i  masked_j[i]              // rotation reduce-tree
//!   zeros_j     = n_bidders − ones_j
//!   tally[j][i] = bitplane[j][i] × zeros_j      // one ct × ct multiply
//! ```
//!
//! The masking step (ct × pt, depth 0) is necessary because unused SIMD
//! slots accumulate encryption noise that would corrupt the all-slot sum.
//!
//! `tally[j][i]` is non-zero only when bidder `i` has a **1** in position
//! `j` while some opponents have a **0** — i.e. bidder `i` is "winning"
//! that bit.  The value equals the number of opponents with a 0.
//!
//! After the ct × ct multiply, each tally ciphertext is **relinearized**
//! back to degree 2 (two polynomials).  This is required because the
//! threshold decryption protocol only handles standard degree-2
//! ciphertexts.
//!
//! ## Threshold Decryption
//!
//! Any 2 of the 3 committee members can jointly decrypt the tally
//! ciphertexts and the second-price bid.  Each participating member
//! computes a **decryption share** (incorporating smudging noise for
//! security), and these shares are combined via Shamir reconstruction
//! to recover the plaintext.
//!
//! ## Ranking (Plaintext Phase)
//!
//! The tally matrix is decrypted and each bidder's row is compared
//! lexicographically (MSB → LSB).  The highest row is the winner; the
//! second-highest identifies the Vickrey price source.  Ties are broken
//! deterministically by slot index (lower wins).
//!
//! The FHE program **never decrypts raw bids**.  The committee uses the
//! ranking to select which input ciphertext to threshold-decrypt (the
//! second-ranked bidder's) to obtain the price.
//!
//! ## Production Considerations
//!
//! **Distributed eval keys.**  The rotation reduce-tree requires Galois
//! (evaluation) keys, and relinearization after the ct × ct multiply
//! requires a relinearization key.  This example now generates both via a
//! distributed MPC flow over the committee's additive BFV secret shares,
//! so the joint secret key is never reconstructed.  The implementation
//! follows the repo design in `EVAL_KEY_MPC_DESIGN.md` and the underlying
//! `trbfv::distributed_eval_key` helpers.
//!
//! **Smudging noise.**  Each BFV decryption leaks a small amount of
//! information about the secret key through the noise term.  Each
//! decryption share includes **smudging noise** — a large random term
//! that statistically drowns the key-dependent component — generated
//! via [`TRBFV::generate_smudging_error`].

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

// ── Constants ────────────────────────────────────────────────────────────────

/// Number of bits per bid.  Bids are `u64`, so 64 bitplanes.
pub const BID_BITS: usize = 64;

/// Polynomial degree = number of SIMD slots.  Caps the maximum bidder count.
pub const SLOTS: usize = 2048;

/// Committee size for the threshold scheme.
pub const COMMITTEE_N: usize = 3;

/// Shamir threshold parameter.  Reconstruction requires `THRESHOLD + 1 = 2`
/// parties.  Constraint: `THRESHOLD <= (COMMITTEE_N - 1) / 2`.
pub const THRESHOLD: usize = 1;

/// Statistical security parameter for smudging noise (bits).
pub const SMUDGING_LAMBDA: usize = 80;

// ── Parameter Setup ──────────────────────────────────────────────────────────

/// Build BFV parameters with SIMD batching enabled.
///
/// * `N = 2048`  — polynomial degree (= number of SIMD slots).
/// * `t = 12289` — plaintext modulus (prime, supports NTT batching).
/// * `6 × 62`-bit coefficient moduli — provides enough noise budget for
///   one multiplication per bitplane plus the rotation reduce-tree.
pub fn build_params() -> Arc<BfvParameters> {
    BfvParametersBuilder::new()
        .set_degree(SLOTS)
        .set_plaintext_modulus(12289)
        .set_moduli_sizes(&[62, 62, 62, 62, 62, 62])
        .build_arc()
        .expect("failed to build BFV parameters")
}

// ── Distributed Key Generation ───────────────────────────────────────────────

/// Generate a common random polynomial (CRP) shared by all committee members.
///
/// In production this would be derived from a public seed; here we sample
/// it randomly.
pub fn generate_crp(params: &Arc<BfvParameters>) -> CommonRandomPoly {
    CommonRandomPoly::new(params, &mut OsRng).expect("CRP generation")
}

/// Generate the shared root seed used to derive distributed eval-key CRS data.
///
/// In production this would be distributed as an explicit protocol step after
/// DKG.  Here we sample it locally once and pass it to every committee member
/// to simulate that broadcast.
pub fn generate_eval_key_root_seed() -> EvalKeyRootSeed {
    let mut root_seed_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut root_seed_bytes);
    EvalKeyRootSeed::new(root_seed_bytes)
}

/// One committee member's keygen output: a secret key share, its public key
/// contribution, and Shamir shares of the secret for distribution.
pub struct MemberKeygenOutput {
    /// This member's BFV secret key (kept private).
    pub sk: SecretKey,
    /// Public key share — sent to aggregator.
    pub pk_share: PublicKeyShare,
    /// Shamir secret shares of `sk`, one per modulus.  `sk_shares[m]` is an
    /// `[n × degree]` matrix; row `i` is the share destined for party `i`.
    pub sk_shares: Vec<Array2<u64>>,
}

/// Run one committee member's key generation.
///
/// 1. Sample a fresh BFV secret key.
/// 2. Compute a public key share from `(sk, crp)`.
/// 3. Shamir-split the secret key polynomial into `COMMITTEE_N` shares.
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

/// Aggregate public key shares into a joint public key.
///
/// Bidders encrypt to this key.  No single committee member knows the
/// corresponding full secret key.
pub fn aggregate_public_key(shares: Vec<PublicKeyShare>) -> PublicKey {
    PublicKey::from_shares(shares).expect("public key aggregation")
}

/// Collect the Shamir shares destined for party `party_idx` (0-based) from
/// all members, then aggregate them into a single secret-key polynomial
/// sum for that party.
///
/// In production, each member sends `sk_shares[m].row(party_idx)` to
/// `party_idx` over a secure channel.  Here we simulate that locally.
pub fn aggregate_sk_shares_for_party(
    all_members_shares: &[Vec<Array2<u64>>],
    party_idx: usize,
    params: &Arc<BfvParameters>,
) -> Poly {
    let share_manager = ShareManager::new(COMMITTEE_N, THRESHOLD, params.clone());

    // Collect the row destined for `party_idx` from each member's Shamir output.
    let collected: Vec<Array2<u64>> = all_members_shares
        .iter()
        .map(|member_shares| {
            // member_shares has one Array2 per modulus; stack them into a
            // single [n_moduli × degree] matrix for this party.
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

// ── Encoding & Encryption ────────────────────────────────────────────────────

/// Decompose a bid into `BID_BITS` sparse plaintexts (one per bitplane).
///
/// Bitplane 0 is the **MSB**.  Only the bidder's assigned `slot` is
/// non-zero in each plaintext; all other slots are 0.
pub fn encode_bid_into_planes(
    bid: u64,
    slot: usize,
    params: &Arc<BfvParameters>,
) -> Vec<Plaintext> {
    assert!(slot < params.degree(), "slot index out of range");

    let degree = params.degree();
    (0..BID_BITS)
        .map(|j| {
            let mut slots = vec![0u64; degree];
            // MSB-first: bitplane 0 = bit 63, bitplane 63 = bit 0.
            slots[slot] = (bid >> (BID_BITS - 1 - j)) & 1;
            Plaintext::try_encode(&slots, Encoding::simd(), params).expect("encode bitplane")
        })
        .collect()
}

/// Encrypt bitplane plaintexts with the joint public key.
///
/// Each bidder calls this with the aggregated committee public key.
pub fn encrypt_bitplanes(planes: &[Plaintext], pk: &PublicKey) -> Vec<Ciphertext> {
    planes
        .iter()
        .map(|pt| pk.try_encrypt(pt, &mut OsRng).expect("encrypt bitplane"))
        .collect()
}

/// Homomorphically add a bidder's encrypted bitplanes into the running
/// global totals (slot-wise addition).
pub fn accumulate_bitplanes(global: &mut [Ciphertext], contribution: &[Ciphertext]) {
    assert_eq!(global.len(), contribution.len(), "bitplane count mismatch");
    for (g, c) in global.iter_mut().zip(contribution.iter()) {
        *g = &*g + c;
    }
}

// ── FHE Tally (Depth 1) ─────────────────────────────────────────────────────

/// Sum all SIMD slots of `ct` into every slot via a rotation reduce-tree.
///
/// BFV SIMD batching with degree `N` arranges `N` slots into **two rows**
/// of `N/2` each.  Column rotations (shifts within a row) reduce each row
/// independently in `log2(N/2)` steps.  A final **row swap + add**
/// combines both halves so every slot holds the global sum `Σ_i ct[i]`.
fn all_slots_sum(ct: &Ciphertext, eval_key: &EvaluationKey) -> Ciphertext {
    // Phase 1: reduce within each row half via column rotations.
    let mut acc = ct.clone();
    let mut shift = 1;
    while shift < SLOTS / 2 {
        let rotated = eval_key
            .rotates_columns_by(&acc, shift)
            .expect("column rotation");
        acc = &acc + &rotated;
        shift *= 2;
    }
    // Phase 2: combine the two row halves via a row swap.
    let row_swapped = eval_key.rotates_rows(&acc).expect("row rotation");
    acc = &acc + &row_swapped;
    acc
}

/// Compute the tally ciphertexts from the accumulated bitplanes.
///
/// For each bitplane `j`:
///
/// 1. Mask out unused SIMD slots (set slots ≥ `n_bidders` to zero).
/// 2. `ones`  = all-slot sum of the masked bitplane.
/// 3. `zeros` = `n_bidders − ones` (broadcast scalar minus ciphertext).
/// 4. `tally` = `bitplane × zeros` — one ct × ct multiply (**depth 1**).
///
/// After the ct × ct multiply, the result is relinearized back to
/// degree 2 so that the threshold decryption protocol (which handles
/// only standard 2-polynomial ciphertexts) can process it correctly.
///
/// The masking step is a ct × pt multiply (depth 0 — free) and is
/// necessary because unused SIMD slots carry accumulated encryption
/// noise that would corrupt the all-slot sum.
pub fn compute_tallies(
    bitplanes: &[Ciphertext],
    n_bidders: usize,
    eval_key: &EvaluationKey,
    relin_key: &RelinearizationKey,
    params: &Arc<BfvParameters>,
) -> Vec<Ciphertext> {
    assert_eq!(bitplanes.len(), BID_BITS, "expected {BID_BITS} bitplanes");
    assert!(n_bidders <= SLOTS, "too many bidders for {SLOTS} slots");
    assert!(
        n_bidders <= (params.plaintext() / 2) as usize,
        "too many bidders for safe decoding under t={}",
        params.plaintext()
    );

    // Mask: 1 in active bidder slots, 0 elsewhere.  Multiplying a
    // ciphertext by this plaintext zeroes out noise in unused slots
    // before the all-slot reduction sum.
    let mut mask_slots = vec![0u64; params.degree()];
    for slot in mask_slots.iter_mut().take(n_bidders) {
        *slot = 1;
    }
    let mask = Plaintext::try_encode(&mask_slots, Encoding::simd(), params).expect("encode mask");

    let n_broadcast = Plaintext::try_encode(
        &vec![n_bidders as u64; params.degree()],
        Encoding::simd(),
        params,
    )
    .expect("encode n_bidders");

    bitplanes
        .iter()
        .map(|bp| {
            let masked = bp * &mask;
            let ones = all_slots_sum(&masked, eval_key);
            let zeros = &n_broadcast - &ones;
            let mut tally = bp * &zeros;
            relin_key.relinearizes(&mut tally).expect("relinearize");
            tally
        })
        .collect()
}

// ── Threshold Decryption ─────────────────────────────────────────────────────

/// Generate smudging noise for one committee member.
///
/// Returns a vector of `BigInt` coefficients that will be converted to a
/// polynomial and added to each decryption share.  The noise magnitude is
/// calculated from the BFV parameters, committee size, number of
/// ciphertexts to decrypt, and the statistical security parameter λ.
pub fn generate_smudging_noise(params: &Arc<BfvParameters>, num_ciphertexts: usize) -> Vec<BigInt> {
    let trbfv = TRBFV::new(COMMITTEE_N, THRESHOLD, params.clone()).expect("TRBFV config");
    trbfv
        .generate_smudging_error(num_ciphertexts, SMUDGING_LAMBDA, &mut OsRng)
        .expect("smudging noise generation")
}

/// Compute one committee member's decryption share for a set of ciphertexts.
///
/// Each participating member calls this with their aggregated SK polynomial
/// sum and their smudging noise.  The shares are later combined via
/// [`threshold_decrypt`].
///
/// `smudging_coeffs` is a single noise polynomial (as BigInt coefficients)
/// shared across all ciphertexts.  For each ciphertext, the same smudging
/// polynomial is used (the bound calculation accounts for this).
pub fn compute_decryption_shares(
    ciphertexts: &[Ciphertext],
    sk_poly_sum: &Poly,
    smudging_coeffs: &[BigInt],
    params: &Arc<BfvParameters>,
) -> Vec<Poly> {
    let share_manager = ShareManager::new(COMMITTEE_N, THRESHOLD, params.clone());

    // Convert BigInt smudging coefficients to a Poly.
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

/// Combine decryption shares from `threshold + 1` parties to recover
/// plaintexts.
///
/// `party_shares` is a slice of `(party_id_1based, shares_for_all_cts)`.
/// Party IDs are **1-based** (matching the Shamir protocol).
pub fn threshold_decrypt(
    party_shares: &[(usize, Vec<Poly>)],
    ciphertexts: &[Ciphertext],
    params: &Arc<BfvParameters>,
) -> Vec<Plaintext> {
    let share_manager = ShareManager::new(COMMITTEE_N, THRESHOLD, params.clone());
    let n_cts = ciphertexts.len();

    let reconstructing_parties: Vec<usize> = party_shares.iter().map(|(id, _)| *id).collect();

    (0..n_cts)
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

// ── Decryption Helpers & Ranking ─────────────────────────────────────────────

/// Decode a single decrypted SIMD slot, treating large values (> t/2) as
/// zero.
///
/// BFV arithmetic is mod `t`.  A true zero can decrypt as `t − ε` due to
/// noise, so any value above `t / 2` is mapped back to 0.
fn decode_slot(raw: u64, plaintext_modulus: u64) -> u64 {
    if raw > plaintext_modulus / 2 {
        0
    } else {
        raw
    }
}

/// Decode threshold-decrypted tally plaintexts into a `[bidder][bit]` matrix.
pub fn decode_tally_matrix(
    tally_pts: &[Plaintext],
    n_bidders: usize,
    params: &Arc<BfvParameters>,
) -> Vec<Vec<u64>> {
    let t = params.plaintext();

    // Decode into [bit][bidder] order first.
    let by_bit: Vec<Vec<u64>> = tally_pts
        .iter()
        .map(|pt| {
            let slots = Vec::<u64>::try_decode(pt, Encoding::simd()).expect("tally decode");
            slots[..n_bidders]
                .iter()
                .map(|&v| decode_slot(v, t))
                .collect()
        })
        .collect();

    // Transpose to [bidder][bit] for easier per-bidder comparison.
    let mut matrix = vec![vec![0u64; BID_BITS]; n_bidders];
    for (j, row) in by_bit.iter().enumerate() {
        for (i, &val) in row.iter().enumerate() {
            matrix[i][j] = val;
        }
    }
    matrix
}

/// Lexicographic comparison of two tally rows (MSB → LSB).
///
/// Returns `true` if `a` strictly beats `b`.  On a perfect tie the lower
/// slot index wins (deterministic public tie-break).
fn tally_row_beats(a: &[u64], a_slot: usize, b: &[u64], b_slot: usize) -> bool {
    for j in 0..BID_BITS {
        match a[j].cmp(&b[j]) {
            std::cmp::Ordering::Greater => return true,
            std::cmp::Ordering::Less => return false,
            std::cmp::Ordering::Equal => {}
        }
    }
    a_slot < b_slot
}

/// Rank bidders by their tally rows and return the winner and runner-up.
///
/// Returns `(winner_slot, Some(second_slot))`.  `second_slot` is `None`
/// only when there is a single bidder.
pub fn rank_bidders(tallies: &[Vec<u64>]) -> (usize, Option<usize>) {
    assert!(!tallies.is_empty(), "no tallies to rank");

    // First pass: find the winner.
    let mut winner = 0;
    for i in 1..tallies.len() {
        if tally_row_beats(&tallies[i], i, &tallies[winner], winner) {
            winner = i;
        }
    }

    // Second pass: find the runner-up (best among non-winners).
    let mut runner_up: Option<usize> = None;
    for i in 0..tallies.len() {
        if i == winner {
            continue;
        }
        runner_up = Some(match runner_up {
            None => i,
            Some(cur) if tally_row_beats(&tallies[i], i, &tallies[cur], cur) => i,
            Some(cur) => cur,
        });
    }

    (winner, runner_up)
}

/// Reconstruct a single bid from threshold-decrypted bitplane plaintexts.
///
/// `bid_pts` are the decrypted plaintexts of this bidder's individual
/// (pre-accumulation) bitplane ciphertexts.
pub fn decode_bid(bid_pts: &[Plaintext], slot: usize, params: &Arc<BfvParameters>) -> u64 {
    assert_eq!(bid_pts.len(), BID_BITS);
    let t = params.plaintext();
    let mut value = 0u64;
    for (j, pt) in bid_pts.iter().enumerate() {
        let slots = Vec::<u64>::try_decode(pt, Encoding::simd()).expect("bitplane decode");
        let bit = decode_slot(slots[slot], t) & 1;
        value |= bit << (BID_BITS - 1 - j);
    }
    value
}

// ── Tests (plaintext-only, no FHE key generation) ────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── decode_slot ──────────────────────────────────────────────────────

    #[test]
    fn decode_slot_zero_stays_zero() {
        assert_eq!(decode_slot(0, 12289), 0);
    }

    #[test]
    fn decode_slot_small_positive_passes_through() {
        assert_eq!(decode_slot(1, 12289), 1);
        assert_eq!(decode_slot(42, 12289), 42);
        assert_eq!(decode_slot(6144, 12289), 6144); // exactly t/2 (integer division)
    }

    #[test]
    fn decode_slot_large_values_mapped_to_zero() {
        // Values above t/2 represent "noisy zeros" in BFV and should map to 0.
        let t: u64 = 12289;
        assert_eq!(decode_slot(t / 2 + 1, t), 0); // 6145
        assert_eq!(decode_slot(t - 1, t), 0); // 12288 — typical noisy zero
        assert_eq!(decode_slot(t, t), 0); // t itself (shouldn't appear, but safe)
    }

    #[test]
    fn decode_slot_boundary_at_half_modulus() {
        let t: u64 = 12289;
        let half = t / 2; // 6144
                          // Exactly at half: passes through.
        assert_eq!(decode_slot(half, t), half);
        // One above half: mapped to zero.
        assert_eq!(decode_slot(half + 1, t), 0);
    }

    // ── tally_row_beats ─────────────────────────────────────────────────

    /// Helper: build a BID_BITS-length row with the given leading values;
    /// the rest are zero.
    fn make_row(leading: &[u64]) -> Vec<u64> {
        let mut row = vec![0u64; BID_BITS];
        for (j, &v) in leading.iter().enumerate() {
            row[j] = v;
        }
        row
    }

    #[test]
    fn tally_row_beats_clear_winner_first_bit() {
        // MSB difference should decide immediately.
        let a = make_row(&[5]);
        let b = make_row(&[3]);
        assert!(tally_row_beats(&a, 0, &b, 1));
        assert!(!tally_row_beats(&b, 1, &a, 0));
    }

    #[test]
    fn tally_row_beats_msb_dominant() {
        // a wins at bit 0, even though b wins at every subsequent bit.
        let mut a = make_row(&[1]);
        let mut b = make_row(&[0]);
        for j in 1..BID_BITS {
            a[j] = 0;
            b[j] = 999;
        }
        assert!(tally_row_beats(&a, 0, &b, 1));
    }

    #[test]
    fn tally_row_beats_tie_broken_by_slot_index() {
        // Identical rows — lower slot index should win.
        let row = make_row(&[3, 2, 1]);
        assert!(tally_row_beats(&row, 0, &row, 1));
        assert!(!tally_row_beats(&row, 1, &row, 0));
    }

    #[test]
    fn tally_row_beats_same_slot_is_false() {
        // A row does NOT beat itself at the same slot (a_slot < b_slot is false).
        let row = make_row(&[3, 2, 1]);
        assert!(!tally_row_beats(&row, 5, &row, 5));
    }

    #[test]
    fn tally_row_beats_later_bit_decides() {
        // Tied at bit 0, decided at bit 1.
        let a = make_row(&[3, 5]);
        let b = make_row(&[3, 2]);
        assert!(tally_row_beats(&a, 0, &b, 1));
        assert!(!tally_row_beats(&b, 1, &a, 0));
    }

    // ── rank_bidders ────────────────────────────────────────────────────

    #[test]
    fn rank_single_bidder() {
        let tallies = vec![make_row(&[1, 0, 1])];
        let (winner, runner) = rank_bidders(&tallies);
        assert_eq!(winner, 0);
        assert_eq!(runner, None);
    }

    #[test]
    fn rank_two_bidders_clear_winner() {
        let tallies = vec![
            make_row(&[0, 1, 0]), // bidder 0
            make_row(&[1, 0, 0]), // bidder 1 — wins at MSB
        ];
        let (winner, runner) = rank_bidders(&tallies);
        assert_eq!(winner, 1);
        assert_eq!(runner, Some(0));
    }

    #[test]
    fn rank_three_bidders_ordering() {
        let tallies = vec![
            make_row(&[0, 0, 5]), // bidder 0 — weakest
            make_row(&[0, 3, 0]), // bidder 1 — middle
            make_row(&[1, 0, 0]), // bidder 2 — strongest (MSB)
        ];
        let (winner, runner) = rank_bidders(&tallies);
        assert_eq!(winner, 2);
        assert_eq!(runner, Some(1));
    }

    #[test]
    fn rank_tie_broken_by_slot_index() {
        // All three bidders have identical tally rows.
        let row = make_row(&[2, 1]);
        let tallies = vec![row.clone(), row.clone(), row.clone()];
        let (winner, runner) = rank_bidders(&tallies);
        // Tie-break: lowest slot index wins.
        assert_eq!(winner, 0);
        assert_eq!(runner, Some(1));
    }

    #[test]
    fn rank_winner_and_runner_tie() {
        // Bidders 0 and 1 tie (both strongest), bidder 2 is weaker.
        let strong = make_row(&[5, 3]);
        let weak = make_row(&[1, 0]);
        let tallies = vec![strong.clone(), strong.clone(), weak];
        let (winner, runner) = rank_bidders(&tallies);
        // Bidder 0 wins tie-break over bidder 1.
        assert_eq!(winner, 0);
        assert_eq!(runner, Some(1));
    }

    #[test]
    fn rank_runner_up_is_second_not_last() {
        // 4 bidders with descending strength — runner-up should be #1, not #3.
        let tallies = vec![
            make_row(&[9, 0, 0, 0]), // bidder 0 — winner
            make_row(&[8, 0, 0, 0]), // bidder 1 — runner-up
            make_row(&[5, 0, 0, 0]), // bidder 2
            make_row(&[1, 0, 0, 0]), // bidder 3
        ];
        let (winner, runner) = rank_bidders(&tallies);
        assert_eq!(winner, 0);
        assert_eq!(runner, Some(1));
    }

    #[test]
    fn rank_msb_dominant_across_bidders() {
        // Bidder 0 has large values in lower bits but 0 at MSB.
        // Bidder 1 has 1 at MSB but 0 everywhere else.
        let mut low_heavy = vec![999u64; BID_BITS];
        low_heavy[0] = 0; // MSB = 0
        let mut msb_only = vec![0u64; BID_BITS];
        msb_only[0] = 1; // MSB = 1
        let tallies = vec![low_heavy, msb_only];
        let (winner, runner) = rank_bidders(&tallies);
        assert_eq!(winner, 1, "MSB=1 bidder must beat MSB=0 bidder");
        assert_eq!(runner, Some(0));
    }

    #[test]
    #[should_panic(expected = "no tallies to rank")]
    fn rank_empty_panics() {
        let tallies: Vec<Vec<u64>> = vec![];
        rank_bidders(&tallies);
    }

    // ── FHE helpers for end-to-end tests ────────────────────────────────

    /// Build the accumulated bitplane ciphertexts directly from a full bid
    /// vector.  This is equivalent to per-bidder encrypt + accumulate but
    /// produces only `BID_BITS` ciphertexts instead of `n × BID_BITS`,
    /// keeping the test runtime manageable for large `n`.
    fn build_accumulated_bitplanes(
        bids: &[u64],
        params: &Arc<BfvParameters>,
        pk: &PublicKey,
    ) -> Vec<Ciphertext> {
        let degree = params.degree();
        (0..BID_BITS)
            .map(|j| {
                let mut slots = vec![0u64; degree];
                for (slot, &bid) in bids.iter().enumerate() {
                    slots[slot] = (bid >> (BID_BITS - 1 - j)) & 1;
                }
                let pt =
                    Plaintext::try_encode(&slots, Encoding::simd(), params).expect("encode plane");
                pk.try_encrypt(&pt, &mut OsRng).expect("encrypt plane")
            })
            .collect()
    }

    /// Plaintext shadow: compute the expected tally matrix the same way
    /// the FHE pipeline does but entirely in the clear.
    ///
    /// For each bitplane `j` and bidder `i`:
    ///   ones_j  = number of active bidders with bit j set
    ///   zeros_j = n_bidders − ones_j
    ///   tally[i][j] = bit_j(bid_i) × zeros_j
    fn plaintext_tally_shadow(bids: &[u64]) -> Vec<Vec<u64>> {
        let n = bids.len();
        let mut matrix = vec![vec![0u64; BID_BITS]; n];
        for j in 0..BID_BITS {
            let ones: u64 = bids.iter().map(|&b| (b >> (BID_BITS - 1 - j)) & 1).sum();
            let zeros = n as u64 - ones;
            for (i, &bid) in bids.iter().enumerate() {
                let bit = (bid >> (BID_BITS - 1 - j)) & 1;
                matrix[i][j] = bit * zeros;
            }
        }
        matrix
    }

    // ── Full-pipeline end-to-end: single bidder ─────────────────────────

    /// End-to-end test with a single bidder: DKG → encode → encrypt →
    /// accumulate → tally → threshold decrypt → rank → verify.
    ///
    /// Confirms the library pipeline works when only one bidder participates:
    /// the winner is correctly identified and `rank_bidders` returns `None`
    /// for the runner-up (no second-price assumption forced).
    #[test]
    fn e2e_single_bidder_pipeline() {
        let params = build_params();

        // ── Committee DKG (3 members) ────────────────────────────────────
        let crp = generate_crp(&params);
        let members: Vec<_> = (0..COMMITTEE_N)
            .map(|_| member_keygen(&params, &crp))
            .collect();

        let pk_shares: Vec<_> = members.iter().map(|m| m.pk_share.clone()).collect();
        let joint_pk = aggregate_public_key(pk_shares);

        let all_sk_shares: Vec<_> = members.iter().map(|m| m.sk_shares.clone()).collect();
        let sk_poly_sums: Vec<_> = (0..COMMITTEE_N)
            .map(|i| aggregate_sk_shares_for_party(&all_sk_shares, i, &params))
            .collect();

        let member_sk_refs: Vec<&_> = members.iter().map(|m| &m.sk).collect();
        let eval_key_root_seed = generate_eval_key_root_seed();
        let (eval_key, relin_key) =
            build_eval_key_from_committee(&member_sk_refs, &params, &eval_key_root_seed);

        let bid: u64 = 7_500_000_000_000_000_000; // 7.5 ETH in wei
        let slot = 0;
        let n_bidders = 1;

        let planes = encode_bid_into_planes(bid, slot, &params);
        let encrypted = encrypt_bitplanes(&planes, &joint_pk);

        // With one bidder the global accumulator is just their ciphertexts.
        let global_bitplanes = encrypted.clone();

        let tally_cts =
            compute_tallies(&global_bitplanes, n_bidders, &eval_key, &relin_key, &params);

        let participating = [0usize, 1];
        let party_tally_shares: Vec<(usize, Vec<_>)> = participating
            .iter()
            .map(|&i| {
                let smudging = generate_smudging_noise(&params, tally_cts.len());
                let shares =
                    compute_decryption_shares(&tally_cts, &sk_poly_sums[i], &smudging, &params);
                (i + 1, shares)
            })
            .collect();

        let tally_pts = threshold_decrypt(&party_tally_shares, &tally_cts, &params);
        let tally_matrix = decode_tally_matrix(&tally_pts, n_bidders, &params);
        let (winner_slot, runner_up) = rank_bidders(&tally_matrix);

        // ── Assertions ───────────────────────────────────────────────────
        assert_eq!(winner_slot, 0, "single bidder must win");
        assert_eq!(
            runner_up, None,
            "single bidder: no runner-up, no forced second-price"
        );

        // Single-bidder tally: for every bit, zeros = n(1) − ones.
        // A '1' bit: tally = 1 × 0 = 0.  A '0' bit: tally = 0 × 1 = 0.
        // The entire row must be zero.
        for &val in &tally_matrix[0] {
            assert_eq!(val, 0, "single-bidder tally must be all zeros");
        }

        // Threshold-decrypt the raw bitplanes to confirm the bid
        // round-trips through FHE correctly.
        let party_bid_shares: Vec<(usize, Vec<_>)> = participating
            .iter()
            .map(|&i| {
                let smudging = generate_smudging_noise(&params, encrypted.len());
                let shares =
                    compute_decryption_shares(&encrypted, &sk_poly_sums[i], &smudging, &params);
                (i + 1, shares)
            })
            .collect();
        let bid_pts = threshold_decrypt(&party_bid_shares, &encrypted, &params);
        let recovered = decode_bid(&bid_pts, slot, &params);
        assert_eq!(recovered, bid, "bid must round-trip through FHE");
    }

    // ── Cross-row-half regression (>1024 bidders) ───────────────────────

    /// Full FHE pipeline with 1025 bidders — enough to span both BFV row
    /// halves (row 0: slots 0..1023, row 1: slots 1024..2047).
    ///
    /// The winner lives in row 1 (slot 1024) and the runner-up in row 0
    /// (slot 500).  Without the row-rotation fix in `all_slots_sum`, the
    /// ones-count would miss row-1 contributions and the tally (hence the
    /// ranking) would be wrong.
    #[test]
    fn fhe_tally_cross_row_halves_1025_bidders() {
        let n_bidders = SLOTS / 2 + 1;

        let params = build_params();
        let crp = generate_crp(&params);
        let members: Vec<_> = (0..COMMITTEE_N)
            .map(|_| member_keygen(&params, &crp))
            .collect();

        let pk_shares: Vec<_> = members.iter().map(|m| m.pk_share.clone()).collect();
        let joint_pk = aggregate_public_key(pk_shares);

        let all_sk_shares: Vec<_> = members.iter().map(|m| m.sk_shares.clone()).collect();
        let sk_poly_sums: Vec<_> = (0..COMMITTEE_N)
            .map(|i| aggregate_sk_shares_for_party(&all_sk_shares, i, &params))
            .collect();

        let member_sk_refs: Vec<&_> = members.iter().map(|m| &m.sk).collect();
        let eval_key_root_seed = generate_eval_key_root_seed();
        let (eval_key, relin_key) =
            build_eval_key_from_committee(&member_sk_refs, &params, &eval_key_root_seed);

        // Winner in row 1 (slot 1024), runner-up in row 0 (slot 500).
        // All other bidders bid 0 → all-zero tally rows → they lose.
        let mut bids = vec![0u64; n_bidders];
        bids[1024] = 1000; // winner   — row 1
        bids[500] = 900; // runner-up — row 0
        bids[0] = 100; // third place — row 0

        let bitplanes = build_accumulated_bitplanes(&bids, &params, &joint_pk);
        let tally_cts = compute_tallies(&bitplanes, n_bidders, &eval_key, &relin_key, &params);

        let participating = [0usize, 1];
        let party_shares: Vec<(usize, Vec<_>)> = participating
            .iter()
            .map(|&i| {
                let smudging = generate_smudging_noise(&params, tally_cts.len());
                let shares =
                    compute_decryption_shares(&tally_cts, &sk_poly_sums[i], &smudging, &params);
                (i + 1, shares)
            })
            .collect();
        let tally_pts = threshold_decrypt(&party_shares, &tally_cts, &params);
        let fhe_matrix = decode_tally_matrix(&tally_pts, n_bidders, &params);
        let (fhe_winner, fhe_runner) = rank_bidders(&fhe_matrix);

        let shadow = plaintext_tally_shadow(&bids);
        let (shadow_winner, shadow_runner) = rank_bidders(&shadow);

        assert_eq!(shadow_winner, 1024, "shadow: expected winner at slot 1024");
        assert_eq!(
            shadow_runner,
            Some(500),
            "shadow: expected runner-up at slot 500"
        );

        assert_eq!(
            fhe_winner, shadow_winner,
            "FHE winner (slot {fhe_winner}) != shadow winner (slot {shadow_winner})"
        );
        assert_eq!(
            fhe_runner, shadow_runner,
            "FHE runner-up ({fhe_runner:?}) != shadow runner-up ({shadow_runner:?})"
        );

        // Spot-check tally values for the three non-zero bidders to
        // verify the row-rotation sum was correct, not just the ranking.
        for &slot in &[0, 500, 1024] {
            for j in 0..BID_BITS {
                assert_eq!(
                    fhe_matrix[slot][j], shadow[slot][j],
                    "tally mismatch at slot {slot}, bit {j}: FHE={}, shadow={}",
                    fhe_matrix[slot][j], shadow[slot][j]
                );
            }
        }
    }

    /// Variant: all non-zero bidders live in row 1 (slots ≥ 1024) while
    /// row 0 is filled with zero bids.  Verifies the row swap propagates
    /// correctly even when active bidders are concentrated in one half.
    #[test]
    fn fhe_tally_bidders_only_in_row1() {
        const N_BIDDERS: usize = 1030;

        let params = build_params();
        let crp = generate_crp(&params);
        let members: Vec<_> = (0..COMMITTEE_N)
            .map(|_| member_keygen(&params, &crp))
            .collect();

        let pk_shares: Vec<_> = members.iter().map(|m| m.pk_share.clone()).collect();
        let joint_pk = aggregate_public_key(pk_shares);

        let all_sk_shares: Vec<_> = members.iter().map(|m| m.sk_shares.clone()).collect();
        let sk_poly_sums: Vec<_> = (0..COMMITTEE_N)
            .map(|i| aggregate_sk_shares_for_party(&all_sk_shares, i, &params))
            .collect();

        let member_sk_refs: Vec<&_> = members.iter().map(|m| &m.sk).collect();
        let eval_key_root_seed = generate_eval_key_root_seed();
        let (eval_key, relin_key) =
            build_eval_key_from_committee(&member_sk_refs, &params, &eval_key_root_seed);

        let mut bids = vec![0u64; N_BIDDERS];
        bids[1024] = 500;
        bids[1025] = 400;
        bids[1026] = 300;
        bids[1027] = 200;
        bids[1028] = 100;
        bids[1029] = 50;

        let bitplanes = build_accumulated_bitplanes(&bids, &params, &joint_pk);
        let tally_cts = compute_tallies(&bitplanes, N_BIDDERS, &eval_key, &relin_key, &params);

        let participating = [0usize, 1];
        let party_shares: Vec<(usize, Vec<_>)> = participating
            .iter()
            .map(|&i| {
                let smudging = generate_smudging_noise(&params, tally_cts.len());
                let shares =
                    compute_decryption_shares(&tally_cts, &sk_poly_sums[i], &smudging, &params);
                (i + 1, shares)
            })
            .collect();
        let tally_pts = threshold_decrypt(&party_shares, &tally_cts, &params);
        let fhe_matrix = decode_tally_matrix(&tally_pts, N_BIDDERS, &params);
        let (fhe_winner, fhe_runner) = rank_bidders(&fhe_matrix);

        let shadow = plaintext_tally_shadow(&bids);
        let (shadow_winner, shadow_runner) = rank_bidders(&shadow);

        assert_eq!(shadow_winner, 1024);
        assert_eq!(shadow_runner, Some(1025));

        assert_eq!(
            fhe_winner, shadow_winner,
            "FHE winner (slot {fhe_winner}) != shadow (slot {shadow_winner})"
        );
        assert_eq!(
            fhe_runner, shadow_runner,
            "FHE runner-up ({fhe_runner:?}) != shadow ({shadow_runner:?})"
        );

        for slot in 1024..1030 {
            for j in 0..BID_BITS {
                assert_eq!(
                    fhe_matrix[slot][j], shadow[slot][j],
                    "tally mismatch at slot {slot}, bit {j}"
                );
            }
        }
    }
}
