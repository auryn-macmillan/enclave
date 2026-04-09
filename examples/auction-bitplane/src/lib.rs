// SPDX-License-Identifier: LGPL-3.0-only
//
//! # Bit-Plane Auction — FHE library
//!
//! A sealed-bid **Vickrey (second-price)** auction built on the BFV
//! fully-homomorphic encryption scheme with SIMD batching.
//!
//! ## Encoding
//!
//! Each bidder is assigned a SIMD **slot** (one per ring position).  A bid
//! of `B` bits is decomposed into `B` *bitplane* ciphertexts — one per bit
//! position, MSB first.  Slot `i` of bitplane `j` holds bit `j` of bidder
//! `i`'s bid.
//!
//! ## Tally (FHE phase — multiplicative depth 1)
//!
//! For each bitplane `j` we compute:
//!
//! ```text
//!   ones_j      = Σ_i  bitplane[j][i]          // rotation reduce-tree
//!   zeros_j     = n_bidders − ones_j
//!   tally[j][i] = bitplane[j][i] × zeros_j     // one ct × ct multiply
//! ```
//!
//! `tally[j][i]` is non-zero only when bidder `i` has a **1** in position
//! `j` while some opponents have a **0** — i.e. bidder `i` is "winning"
//! that bit.  The value equals the number of opponents with a 0.
//!
//! ## Ranking (plaintext phase)
//!
//! The tally matrix is decrypted and each bidder's row is compared
//! lexicographically (MSB → LSB).  The highest row is the winner; the
//! second-highest identifies the Vickrey price source.  Ties are broken
//! deterministically by slot index (lower wins).
//!
//! The FHE program **never decrypts raw bids**.  In production a
//! decryption committee would use the ranking to select which input
//! ciphertext to decrypt (the second-ranked bidder's) to obtain the price.

use fhe::bfv::{
    BfvParameters, BfvParametersBuilder, Ciphertext, Encoding, EvaluationKey, EvaluationKeyBuilder,
    Plaintext, RelinearizationKey, SecretKey,
};
use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};
use rand::rngs::OsRng;
use std::sync::Arc;

// ── Constants ────────────────────────────────────────────────────────────────

/// Number of bits per bid.  Bids are `u64`, so 64 bitplanes.
pub const BID_BITS: usize = 64;

/// Polynomial degree = number of SIMD slots.  Caps the maximum bidder count.
pub const SLOTS: usize = 2048;

// ── Parameter & Key Setup ────────────────────────────────────────────────────

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

/// Build an evaluation key that supports the rotation reduce-tree.
///
/// The all-slot sum needs column rotations by every power of two from 1
/// up to `SLOTS / 2` (exclusive).  With `SLOTS = 2048` that means shifts
/// of 1, 2, 4, 8, …, 512 — ten rotations per bitplane.
pub fn build_eval_key(sk: &SecretKey) -> EvaluationKey {
    let mut builder = EvaluationKeyBuilder::new(sk).expect("eval key builder");
    let mut shift = 1;
    while shift < SLOTS / 2 {
        builder
            .enable_column_rotation(shift)
            .expect("enable rotation");
        shift *= 2;
    }
    builder.build(&mut OsRng).expect("build evaluation key")
}

/// Build a relinearization key (required after every ct × ct multiply to
/// keep the ciphertext size at two polynomials).
pub fn build_relin_key(sk: &SecretKey) -> RelinearizationKey {
    RelinearizationKey::new(sk, &mut OsRng).expect("build relinearization key")
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

/// Encrypt bitplane plaintexts with a secret key.
///
/// In production, bidders would encrypt with the *public* key.  The demo
/// uses the secret key for simplicity (the ciphertexts are identically
/// distributed either way).
pub fn encrypt_bitplanes(planes: &[Plaintext], sk: &SecretKey) -> Vec<Ciphertext> {
    planes
        .iter()
        .map(|pt| sk.try_encrypt(pt, &mut OsRng).expect("encrypt bitplane"))
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

// ── FHE Tally (depth 1) ─────────────────────────────────────────────────────

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

/// Multiply two ciphertexts and immediately relinearize.
fn mul_relin(a: &Ciphertext, b: &Ciphertext, rk: &RelinearizationKey) -> Ciphertext {
    let mut product = a * b;
    rk.relinearizes(&mut product).expect("relinearize");
    product
}

/// Compute the tally ciphertexts from the accumulated bitplanes.
///
/// For each bitplane `j`:
///
/// 1. `ones`  = all-slot sum of the bitplane (how many bidders have a 1).
/// 2. `zeros` = `n_bidders − ones` (broadcast scalar minus ciphertext).
/// 3. `tally` = `bitplane × zeros` — one ct × ct multiply (**depth 1**).
///
/// The result for slot `i` is: "if my bit is 1, how many opponents have 0?"
pub fn compute_tallies(
    bitplanes: &[Ciphertext],
    n_bidders: usize,
    eval_key: &EvaluationKey,
    rk: &RelinearizationKey,
    params: &Arc<BfvParameters>,
) -> Vec<Ciphertext> {
    assert_eq!(bitplanes.len(), BID_BITS, "expected {BID_BITS} bitplanes");
    assert!(n_bidders <= SLOTS, "too many bidders for {SLOTS} slots");
    assert!(
        n_bidders <= (params.plaintext() / 2) as usize,
        "too many bidders for safe decoding under t={}",
        params.plaintext()
    );

    let n_broadcast = Plaintext::try_encode(
        &vec![n_bidders as u64; params.degree()],
        Encoding::simd(),
        params,
    )
    .expect("encode n_bidders");

    bitplanes
        .iter()
        .map(|bp| {
            let ones = all_slots_sum(bp, eval_key);
            let zeros = &n_broadcast - &ones;
            mul_relin(bp, &zeros, rk)
        })
        .collect()
}

// ── Decryption & Ranking (plaintext phase) ───────────────────────────────────

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

/// Decrypt the tally ciphertexts into a `[bidder][bit]` matrix.
pub fn decrypt_tally_matrix(
    tally_cts: &[Ciphertext],
    n_bidders: usize,
    sk: &SecretKey,
    params: &Arc<BfvParameters>,
) -> Vec<Vec<u64>> {
    let t = params.plaintext();

    // Decrypt into [bit][bidder] order first.
    let by_bit: Vec<Vec<u64>> = tally_cts
        .iter()
        .map(|ct| {
            let pt = sk.try_decrypt(ct).expect("tally decryption");
            let slots = Vec::<u64>::try_decode(&pt, Encoding::simd()).expect("tally decode");
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

// ── Top-level API ────────────────────────────────────────────────────────────

/// Run the full Vickrey auction: compute tallies, decrypt, rank.
///
/// Returns `(winner_slot, second_slot)`.  The caller (or decryption
/// committee) uses `second_slot` to identify whose bid to decrypt for the
/// Vickrey price.
pub fn find_winner(
    bitplanes: &[Ciphertext],
    n_bidders: usize,
    eval_key: &EvaluationKey,
    rk: &RelinearizationKey,
    sk: &SecretKey,
    params: &Arc<BfvParameters>,
) -> (usize, Option<usize>) {
    let tally_cts = compute_tallies(bitplanes, n_bidders, eval_key, rk, params);
    let tally_matrix = decrypt_tally_matrix(&tally_cts, n_bidders, sk, params);
    rank_bidders(&tally_matrix)
}

/// Decrypt a single bidder's bid from their individual (pre-accumulation)
/// bitplane ciphertexts.
///
/// Used in the demo to verify the Vickrey price: the committee would
/// decrypt `bid_cts[second_slot]` to learn the price the winner pays.
pub fn decrypt_bid(
    bid_cts: &[Ciphertext],
    slot: usize,
    sk: &SecretKey,
    params: &Arc<BfvParameters>,
) -> u64 {
    assert_eq!(bid_cts.len(), BID_BITS);
    let t = params.plaintext();
    let mut value = 0u64;
    for (j, ct) in bid_cts.iter().enumerate() {
        let pt = sk.try_decrypt(ct).expect("bitplane decryption");
        let slots = Vec::<u64>::try_decode(&pt, Encoding::simd()).expect("bitplane decode");
        let bit = decode_slot(slots[slot], t) & 1;
        value |= bit << (BID_BITS - 1 - j);
    }
    value
}
