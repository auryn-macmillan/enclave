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
//! **Eval key shortcut.**  The rotation reduce-tree requires a Galois
//! (evaluation) key, and relinearization after the ct × ct multiply
//! requires a relinearization key.  The `fhe` library can only build
//! these from a full secret key — no multiparty key generation protocol
//! exists in the library.  This demo reconstructs the full secret key
//! *temporarily* to build both keys, then immediately discards it.  DKG
//! and threshold decryption remain fully distributed.  A production
//! system would need an MPC protocol for these keys (e.g. the approach
//! in Mouchet et al., "Multiparty Homomorphic Encryption from
//! Ring-Learning-with-Errors").
//!
//! **Smudging noise.**  Each BFV decryption leaks a small amount of
//! information about the secret key through the noise term.  Each
//! decryption share includes **smudging noise** — a large random term
//! that statistically drowns the key-dependent component — generated
//! via [`TRBFV::generate_smudging_error`].

use fhe::bfv::{
    BfvParameters, BfvParametersBuilder, Ciphertext, Encoding, EvaluationKey, EvaluationKeyBuilder,
    Plaintext, PublicKey, RelinearizationKey, SecretKey,
};
use fhe::mbfv::{Aggregate, CommonRandomPoly, PublicKeyShare};
use fhe::trbfv::{ShareManager, TRBFV};
use fhe_math::rq::{traits::TryConvertFrom, Poly, Representation};
use fhe_traits::{FheDecoder, FheEncoder, FheEncrypter};
use ndarray::Array2;
use num_bigint::BigInt;
use rand::rngs::OsRng;
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
        .generate_secret_shares_from_poly(sk_poly, &mut OsRng)
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

// ── Eval Key (Option C — reconstruct full SK temporarily) ────────────────────

/// Build an evaluation key and relinearization key by temporarily
/// reconstructing the full secret key from all committee members' raw
/// secret keys.
///
/// **This is a demo shortcut.**  The full secret key is summed, used to
/// build both keys, and immediately dropped.  In production, an MPC
/// Galois key generation protocol would be used instead.
///
/// The all-slot sum needs column rotations by every power of two from 1
/// up to `SLOTS / 2` (exclusive).  With `SLOTS = 2048` that means shifts
/// of 1, 2, 4, 8, …, 512 — ten rotations per bitplane.
pub fn build_eval_key_from_committee(
    member_sks: &[&SecretKey],
    params: &Arc<BfvParameters>,
) -> (EvaluationKey, RelinearizationKey) {
    // Sum all secret key polynomials to reconstruct the joint secret key.
    // The joint SK = Σ sk_i, matching the aggregated public key PK = Σ pk_i.
    let ctx = params.ctx_at_level(0).expect("context at level 0");

    let mut combined = Poly::zero(ctx, Representation::PowerBasis);
    for sk in member_sks {
        let sk_poly =
            Poly::try_convert_from(sk.coeffs.as_ref(), ctx, false, Representation::PowerBasis)
                .expect("sk → poly");
        combined = &combined + &sk_poly;
    }

    // Reconstruct a SecretKey from the combined polynomial's coefficients.
    let combined_coeffs = combined.coefficients();
    // The coefficients matrix is [n_moduli × degree]; we need just the
    // first modulus row as i64 values for SecretKey construction.
    let row = combined_coeffs.row(0);
    let degree = params.degree();
    let modulus = params.moduli()[0];
    let coeffs_i64: Box<[i64]> = row
        .iter()
        .take(degree)
        .map(|&v| {
            // Map unsigned residue back to centered representation.
            if v > modulus / 2 {
                v as i64 - modulus as i64
            } else {
                v as i64
            }
        })
        .collect();

    let combined_sk = SecretKey::new(coeffs_i64.into_vec(), &params);

    let mut builder = EvaluationKeyBuilder::new(&combined_sk).expect("eval key builder");
    let mut shift = 1;
    while shift < SLOTS / 2 {
        builder
            .enable_column_rotation(shift)
            .expect("enable rotation");
        shift *= 2;
    }
    let eval_key = builder.build(&mut OsRng).expect("build evaluation key");
    let relin_key =
        RelinearizationKey::new(&combined_sk, &mut OsRng).expect("build relinearization key");
    (eval_key, relin_key)
    // `combined_sk` is dropped here — the full secret key no longer exists.
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
/// After `log2(SLOTS/2)` steps each slot holds `Σ_i ct[i]`.
fn all_slots_sum(ct: &Ciphertext, eval_key: &EvaluationKey) -> Ciphertext {
    let mut acc = ct.clone();
    let mut shift = 1;
    while shift < SLOTS / 2 {
        let rotated = eval_key
            .rotates_columns_by(&acc, shift)
            .expect("column rotation");
        acc = &acc + &rotated;
        shift *= 2;
    }
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
    for s in 0..n_bidders {
        mask_slots[s] = 1;
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
