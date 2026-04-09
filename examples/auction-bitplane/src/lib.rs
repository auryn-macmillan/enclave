// SPDX-License-Identifier: LGPL-3.0-only
//
// Bit-plane auction FHE library — horizontal SIMD encoding.
//
// Each bidder occupies a SIMD slot.  For each of the B bit planes we keep
// one packed ciphertext whose slot i holds bit j of bidder i's bid.
//
// At close the server computes per-plane tallies entirely in ciphertext
// (one ct–ct multiply per plane, depth 1) and decrypts only the tally
// matrix, never the raw bids.

use fhe::bfv::{
    BfvParameters, BfvParametersBuilder, Ciphertext, Encoding, EvaluationKey, EvaluationKeyBuilder,
    Plaintext, RelinearizationKey, SecretKey,
};
use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};
use rand::rngs::OsRng;
use std::sync::Arc;

// ── Constants ────────────────────────────────────────────────────────────────

/// Number of bits used to represent each bid (MSB-first across bit planes).
pub const BID_BITS: usize = 64;

/// Maximum number of SIMD slots (= polynomial degree in BFV batching).
/// Each bidder is assigned one slot, so this also caps the bidder count.
pub const SLOTS: usize = 2048;

// ── Parameter & Key Setup ────────────────────────────────────────────────────

/// Build SIMD-friendly BFV parameters.
///
/// N = 2048, t = 12289 (prime, 12289 mod 4096 == 1), 6×62-bit moduli.
pub fn build_params() -> Arc<BfvParameters> {
    BfvParametersBuilder::new()
        .set_degree(SLOTS)
        .set_plaintext_modulus(12289)
        .set_moduli_sizes(&[62, 62, 62, 62, 62, 62])
        .build_arc()
        .expect("failed to build BFV parameters")
}

/// Build an evaluation key with column rotations needed for the all-slot sum.
///
/// We need shifts by powers of two from 1 up to SLOTS/2 so that the
/// reduce-tree can broadcast the slot sum to every position.
pub fn build_eval_key(sk: &SecretKey) -> EvaluationKey {
    let mut builder = EvaluationKeyBuilder::new(sk).expect("failed to create eval key builder");
    let mut shift = 1;
    while shift < SLOTS / 2 {
        builder
            .enable_column_rotation(shift)
            .expect("failed to enable column rotation");
        shift *= 2;
    }
    builder
        .build(&mut OsRng)
        .expect("failed to build evaluation key")
}

/// Build a relinearization key (used after ct × ct multiplies).
pub fn build_relin_key(sk: &SecretKey) -> RelinearizationKey {
    RelinearizationKey::new(sk, &mut OsRng).expect("failed to build relinearization key")
}

// ── Low-level Helpers ────────────────────────────────────────────────────────

/// Multiply two ciphertexts and relinearize.
pub fn mul_relin(a: &Ciphertext, b: &Ciphertext, rk: &RelinearizationKey) -> Ciphertext {
    let mut result = a * b;
    rk.relinearizes(&mut result)
        .expect("relinearization failed");
    result
}

// ── Horizontal Bit-Plane Encoding ────────────────────────────────────────────

/// Encode a single bidder's bid into `BID_BITS` sparse plaintexts.
///
/// For each bit plane j (j = 0 is MSB), the returned plaintext has the
/// bidder's bit in `slot` and zeros everywhere else.
pub fn encode_bid_into_planes(
    value: u64,
    slot: usize,
    params: &Arc<BfvParameters>,
) -> Vec<Plaintext> {
    assert!(slot < params.degree(), "slot index out of range");

    let degree = params.degree();
    (0..BID_BITS)
        .map(|j| {
            let mut slots = vec![0u64; degree];
            slots[slot] = (value >> (BID_BITS - 1 - j)) & 1;
            Plaintext::try_encode(&slots, Encoding::simd(), params)
                .expect("failed to encode bitplane")
        })
        .collect()
}

/// Encrypt a set of bitplane plaintexts with the secret key (for demos).
pub fn encrypt_bitplanes_sk(planes: &[Plaintext], sk: &SecretKey) -> Vec<Ciphertext> {
    planes
        .iter()
        .map(|pt| {
            sk.try_encrypt(pt, &mut OsRng)
                .expect("failed to encrypt bitplane")
        })
        .collect()
}

/// Add a bidder's encrypted bitplane contribution into the running totals.
///
/// `global_planes` must already be initialised (e.g. with the first
/// bidder's contribution or via [`init_bitplanes`]).
pub fn accumulate_bitplanes(global_planes: &mut [Ciphertext], contribution: &[Ciphertext]) {
    assert_eq!(
        global_planes.len(),
        contribution.len(),
        "bitplane count mismatch"
    );
    for (gp, cp) in global_planes.iter_mut().zip(contribution.iter()) {
        *gp = &*gp + cp;
    }
}

/// Decrypt a bidder's bid from their individual bitplane ciphertexts.
///
/// In a Vickrey auction the committee uses this to recover the second-ranked
/// bid (the price the winner pays).  `bitplanes` are the **per-bidder**
/// contribution ciphertexts (before accumulation), and `slot` is the
/// bidder's assigned SIMD slot.
pub fn decrypt_bid_from_bitplanes(
    bitplanes: &[Ciphertext],
    slot: usize,
    sk: &SecretKey,
    params: &Arc<BfvParameters>,
) -> u64 {
    assert_eq!(bitplanes.len(), BID_BITS);
    let half_t = params.plaintext() / 2;
    let mut value = 0u64;
    for (j, ct) in bitplanes.iter().enumerate() {
        let pt = sk.try_decrypt(ct).expect("bitplane decryption failed");
        let slots = Vec::<u64>::try_decode(&pt, Encoding::simd()).expect("bitplane decode failed");
        let bit = if slots[slot] > half_t {
            0u64
        } else {
            slots[slot] & 1
        };
        value |= bit << (BID_BITS - 1 - j);
    }
    value
}

// ── All-Slot Sum (Rotation Reduce-Tree) ──────────────────────────────────────

/// Compute the all-slot sum of a packed ciphertext via a rotation tree.
///
/// Returns a ciphertext where **every** slot holds `Σ_i ct[i]`.
/// Requires `log2(SLOTS)` rotations and additions.
pub fn all_slots_sum(ct: &Ciphertext, eval_key: &EvaluationKey) -> Ciphertext {
    let mut acc = ct.clone();
    let mut shift = 1;
    while shift < SLOTS / 2 {
        let rotated = eval_key
            .rotates_columns_by(&acc, shift)
            .expect("column rotation failed in all_slots_sum");
        acc = &acc + &rotated;
        shift *= 2;
    }
    acc
}

// ── Tally Computation ────────────────────────────────────────────────────────

/// Compute the tally ciphertexts from the global bitplane ciphertexts.
///
/// For each bit plane j the tally is:
///
/// ```text
///   tally[j][i] = bitplane[j][i] × (n_bidders − ones_j)
/// ```
///
/// where `ones_j = Σ_i bitplane[j][i]`.  Slot i therefore gets the count
/// of opponents whose bit j is 0 **if** bidder i's bit j is 1, and 0
/// otherwise.  Multiplicative depth: **1**.
pub fn compute_tallies(
    bitplanes: &[Ciphertext],
    n_bidders: usize,
    eval_key: &EvaluationKey,
    rk: &RelinearizationKey,
    params: &Arc<BfvParameters>,
) -> Vec<Ciphertext> {
    assert_eq!(bitplanes.len(), BID_BITS, "expected {BID_BITS} bitplanes");
    assert!(
        n_bidders <= SLOTS,
        "too many bidders ({n_bidders}) for {SLOTS} slots"
    );
    assert!(
        n_bidders <= (params.plaintext() / 2) as usize,
        "too many bidders for safe tally decoding under t={}",
        params.plaintext()
    );

    bitplanes
        .iter()
        .map(|bp| {
            // ones_ct: every slot = count of 1s in this plane
            let ones_ct = all_slots_sum(bp, eval_key);
            // zeros_ct: every slot = n_bidders − ones
            let zeros_ct = &Plaintext::try_encode(
                &vec![n_bidders as u64; params.degree()],
                Encoding::simd(),
                params,
            )
            .expect("encode n")
                - &ones_ct;
            // tally = bp[i] × zeros  (depth 1)
            mul_relin(bp, &zeros_ct, rk)
        })
        .collect()
}

// ── Decryption & Ranking ─────────────────────────────────────────────────────

/// Decrypt the tally ciphertexts into a matrix `T[bidder][bit]`.
pub fn decrypt_tally_matrix(
    tally_cts: &[Ciphertext],
    n_bidders: usize,
    sk: &SecretKey,
    params: &Arc<BfvParameters>,
) -> Vec<Vec<u64>> {
    let half_t = params.plaintext() / 2;
    tally_cts
        .iter()
        .map(|ct| {
            let pt = sk.try_decrypt(ct).expect("tally decryption failed");
            let slots = Vec::<u64>::try_decode(&pt, Encoding::simd()).expect("tally decode failed");
            slots[..n_bidders]
                .iter()
                .map(|&v| if v > half_t { 0 } else { v })
                .collect()
        })
        .collect::<Vec<Vec<u64>>>()
        // Transpose: convert from [bit][bidder] to [bidder][bit]
        .into_iter()
        .enumerate()
        .fold(
            vec![vec![0u64; BID_BITS]; n_bidders],
            |mut matrix, (j, per_bidder)| {
                for (i, &val) in per_bidder.iter().enumerate() {
                    matrix[i][j] = val;
                }
                matrix
            },
        )
}

/// Return `true` if `candidate`'s tally row lexicographically beats
/// `current`'s, using slot index as a deterministic tie-breaker.
pub fn candidate_beats_current(
    candidate_tallies: &[u64],
    current_tallies: &[u64],
    candidate_slot: usize,
    current_slot: usize,
) -> bool {
    for j in 0..BID_BITS {
        match candidate_tallies[j].cmp(&current_tallies[j]) {
            std::cmp::Ordering::Greater => return true,
            std::cmp::Ordering::Less => return false,
            std::cmp::Ordering::Equal => {}
        }
    }
    // Deterministic public tie-break: lower slot wins.
    candidate_slot < current_slot
}

/// Identify the winner and second-ranked bidder from the decrypted tally
/// matrix (Vickrey auction: winner pays the second-highest price).
///
/// Returns `(winner_slot, second_slot)`.  `second_slot` is `None` when
/// there is only one bidder.  The committee decrypts the bid ciphertext at
/// `second_slot` to obtain the price the winner pays.
pub fn rank_bidders_from_tallies(tallies: &[Vec<u64>]) -> (usize, Option<usize>) {
    assert!(!tallies.is_empty(), "no tallies to rank");
    for tally in tallies {
        assert!(
            tally.len() >= BID_BITS,
            "each tally row must have at least {BID_BITS} entries"
        );
    }

    let mut winner_idx = 0;
    for i in 1..tallies.len() {
        if candidate_beats_current(&tallies[i], &tallies[winner_idx], i, winner_idx) {
            winner_idx = i;
        }
    }

    // Second pass: find runner-up (best among all non-winners).
    let second_idx = if tallies.len() < 2 {
        None
    } else {
        let mut runner_up: Option<usize> = None;
        for i in 0..tallies.len() {
            if i == winner_idx {
                continue;
            }
            match runner_up {
                None => runner_up = Some(i),
                Some(current) => {
                    if candidate_beats_current(&tallies[i], &tallies[current], i, current) {
                        runner_up = Some(i);
                    }
                }
            }
        }
        runner_up
    };

    (winner_idx, second_idx)
}

// ── Top-Level Find-Winner ────────────────────────────────────────────────────

/// Run the full horizontal bitplane Vickrey auction on pre-accumulated
/// bitplanes.
///
/// Returns `(winner_slot, second_slot)`.  The committee decrypts the bid
/// at `second_slot` to determine the price the winner pays.
pub fn find_winner_bitplane(
    bitplanes: &[Ciphertext],
    n_bidders: usize,
    eval_key: &EvaluationKey,
    rk: &RelinearizationKey,
    sk: &SecretKey,
    params: &Arc<BfvParameters>,
) -> (usize, Option<usize>) {
    let tally_cts = compute_tallies(bitplanes, n_bidders, eval_key, rk, params);
    let tally_matrix = decrypt_tally_matrix(&tally_cts, n_bidders, sk, params);
    rank_bidders_from_tallies(&tally_matrix)
}
