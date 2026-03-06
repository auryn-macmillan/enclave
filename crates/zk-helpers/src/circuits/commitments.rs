// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Commitment computation functions for zero-knowledge circuits.
//!
//! This module provides functions to compute commitments to various cryptographic objects
//! (polynomials, public keys, secret keys, shares, etc.) using raw Poseidon2 hashing.
//!
//! All functions match the corresponding Noir circuit implementations in
//! `circuits/lib/src/math/poseidon2_commitment.nr` exactly.
//!
//! NOTE: Challenge derivation functions have been removed — challenges are now
//! derived by the proving backend via `std::phase::challenge()` (PhaseBarrier).

use crate::packing::flatten;
use ark_bn254::Fr as Field;
use ark_ff::BigInteger;
use ark_ff::PrimeField;
use e3_polynomial::{CrtPolynomial, Polynomial};
use num_bigint::BigInt;
use std::slice::from_ref;
use taceo_poseidon2::bn254::t4::permutation as poseidon2_permutation;

// ============================================================================
// DOMAIN SEPARATORS
// ============================================================================

/// String: "PK"
const DS_PK: [u8; 64] = [
    0x50, 0x4b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// String: "PK_GENERATION"
const DS_PK_GENERATION: [u8; 64] = [
    0x50, 0x4b, 0x5f, 0x47, 0x45, 0x4e, 0x45, 0x52, 0x41, 0x54, 0x49, 0x4f, 0x4e, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// String: "SHARE_COMPUTATION"
const DS_SHARE_COMPUTATION: [u8; 64] = [
    0x53, 0x48, 0x41, 0x52, 0x45, 0x5f, 0x43, 0x4f, 0x4d, 0x50, 0x55, 0x54, 0x41, 0x54, 0x49, 0x4f,
    0x4e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// String: "SHARE_ENCRYPTION"
const DS_SHARE_ENCRYPTION: [u8; 64] = [
    0x53, 0x48, 0x41, 0x52, 0x45, 0x5f, 0x45, 0x4e, 0x43, 0x52, 0x59, 0x50, 0x54, 0x49, 0x4f, 0x4e,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// String: "PK_AGGREGATION"
const DS_PK_AGGREGATION: [u8; 64] = [
    0x50, 0x4b, 0x5f, 0x41, 0x47, 0x47, 0x52, 0x45, 0x47, 0x41, 0x54, 0x49, 0x4f, 0x4e, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Domain separator for general-purpose ciphertext commitments.
/// String: "CIPHERTEXT"
const DS_CIPHERTEXT: [u8; 64] = [
    0x43, 0x49, 0x50, 0x48, 0x45, 0x52, 0x54, 0x45, 0x58, 0x54, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// String: "AGGREGATED_SHARES"
const DS_AGGREGATED_SHARES: [u8; 64] = [
    0x41, 0x47, 0x47, 0x52, 0x45, 0x47, 0x41, 0x54, 0x45, 0x44, 0x5f, 0x53, 0x48, 0x41, 0x52, 0x45,
    0x53, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// String: "RECURSIVE_AGGREGATION"
const DS_RECURSIVE_AGGREGATION: [u8; 64] = [
    0x52, 0x45, 0x43, 0x55, 0x52, 0x53, 0x49, 0x56, 0x45, 0x5f, 0x41, 0x47, 0x47, 0x52, 0x45, 0x47,
    0x41, 0x54, 0x49, 0x4f, 0x4e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// ============================================================================
// RAW POSEIDON2 HASH
// ============================================================================

/// Convert a 64-byte domain separator to a Field element by interpreting
/// the first 31 bytes as a big-endian integer.
///
/// Matches the Noir `domain_separator_to_field` function exactly.
fn domain_separator_to_field(ds: &[u8; 64]) -> Field {
    let mut result = Field::from(0u64);
    let f256 = Field::from(256u64);
    for i in 0..31 {
        result = result * f256 + Field::from(ds[i] as u64);
    }
    result
}

/// Raw Poseidon2 sponge hash over a slice of Fields with domain separation.
///
/// Uses the standard Poseidon2 sponge construction (rate=3, capacity=1)
/// with IV = message_length * 2^64 (matching noir_stdlib's Poseidon2).
///
/// Domain separation is achieved by prepending the domain separator as
/// the first absorbed element, which is included in the message length.
///
/// This matches the Noir `poseidon2_hash` function in `poseidon2_commitment.nr` exactly.
pub fn poseidon2_hash(inputs: &[Field], domain_separator: &[u8; 64]) -> Field {
    let ds_field = domain_separator_to_field(domain_separator);
    let total_len = inputs.len() + 1; // +1 for domain separator prefix

    // IV encodes the message length (matches noir_stdlib Poseidon2 convention)
    // 2^64 = 18446744073709551616
    let two_pow_64 = Field::from(18446744073709551616u128);
    let iv = Field::from(total_len as u64) * two_pow_64;

    // Initialize sponge state: [0, 0, 0, iv]
    let mut state = [Field::from(0u64), Field::from(0u64), Field::from(0u64), iv];
    let mut cache = [Field::from(0u64); 3];
    let mut cache_size: usize = 1;

    // Absorb domain separator prefix
    cache[0] = ds_field;

    // Absorb all input elements
    for input in inputs {
        if cache_size == 3 {
            // Cache full — add to state and permute
            state[0] += cache[0];
            state[1] += cache[1];
            state[2] += cache[2];
            state = poseidon2_permutation(&state);
            cache[0] = *input;
            cache_size = 1;
        } else {
            cache[cache_size] = *input;
            cache_size += 1;
        }
    }

    // Final squeeze: add remaining cache to state and permute
    for j in 0..3 {
        if j < cache_size {
            state[j] += cache[j];
        }
    }
    state = poseidon2_permutation(&state);

    // Return first element of permuted state
    state[0]
}

// ============================================================================
// COMMITMENTS
// ============================================================================

/// Compute a commitment to the correct DKG public key polynomials by flattening them and hashing.
///
/// Matches the Noir `compute_dkg_pk_commitment` function (raw Poseidon2).
///
/// # Arguments
/// * `pk0` - First component of the correct DKG public key (one vector per modulus)
/// * `pk1` - Second component of the correct DKG public key (one vector per modulus)
/// * `bit_pk` - The bit width for public key coefficient bounds
///
/// # Returns
/// A `BigInt` representing the commitment hash value
pub fn compute_dkg_pk_commitment(pk0: &CrtPolynomial, pk1: &CrtPolynomial, bit_pk: u32) -> BigInt {
    let mut payload = Vec::new();
    payload = flatten(payload, &pk0.limbs, bit_pk);
    payload = flatten(payload, &pk1.limbs, bit_pk);

    let commitment_field = poseidon2_hash(&payload, &DS_PK);
    let commitment_bytes = commitment_field.into_bigint().to_bytes_le();
    BigInt::from_bytes_le(num_bigint::Sign::Plus, &commitment_bytes)
}

/// Compute a commitment to the threshold public key polynomials by flattening them and hashing.
///
/// Matches the Noir `compute_threshold_pk_commitment` function (raw Poseidon2).
///
/// # Arguments
/// * `pk0` - First component of the threshold public key (CRT limbs)
/// * `pk1` - Second component of the threshold public key (CRT limbs)
/// * `bit_pk` - The bit width for public key coefficient bounds
///
/// # Returns
/// A `BigInt` representing the commitment hash value
pub fn compute_threshold_pk_commitment(
    pk0: &CrtPolynomial,
    pk1: &CrtPolynomial,
    bit_pk: u32,
) -> BigInt {
    let mut payload = Vec::new();
    payload = flatten(payload, &pk0.limbs, bit_pk);
    payload = flatten(payload, &pk1.limbs, bit_pk);

    let commitment_field = poseidon2_hash(&payload, &DS_PK_GENERATION);
    let commitment_bytes = commitment_field.into_bigint().to_bytes_le();
    BigInt::from_bytes_le(num_bigint::Sign::Plus, &commitment_bytes)
}

/// Compute a commitment to the threshold secret key share by flattening it and hashing.
///
/// Matches the Noir `compute_share_computation_sk_commitment` function (raw Poseidon2).
///
/// # Arguments
/// * `sk` - Threshold secret key polynomial
/// * `bit_sk` - The bit width for threshold secret key share coefficient bounds
///
/// # Returns
/// A `BigInt` representing the commitment hash value
pub fn compute_share_computation_sk_commitment(sk: &Polynomial, bit_sk: u32) -> BigInt {
    let mut payload = Vec::new();
    payload = flatten(payload, from_ref(sk), bit_sk);

    let commitment_field = poseidon2_hash(&payload, &DS_SHARE_COMPUTATION);
    let commitment_bytes = commitment_field.into_bigint().to_bytes_le();
    BigInt::from_bytes_le(num_bigint::Sign::Plus, &commitment_bytes)
}

/// Compute a commitment to the threshold smudging noise share by flattening it and hashing.
///
/// Matches the Noir `compute_share_computation_e_sm_commitment` function (raw Poseidon2).
///
/// # Arguments
/// * `e_sm` - Threshold smudging noise polynomial (CRT limbs)
/// * `bit_e_sm` - The bit width for threshold smudging noise share coefficient bounds
///
/// # Returns
/// A `BigInt` representing the commitment hash value
pub fn compute_share_computation_e_sm_commitment(e_sm: &CrtPolynomial, bit_e_sm: u32) -> BigInt {
    let mut payload = Vec::new();
    payload = flatten(payload, &e_sm.limbs, bit_e_sm);

    let commitment_field = poseidon2_hash(&payload, &DS_SHARE_COMPUTATION);
    let commitment_bytes = commitment_field.into_bigint().to_bytes_le();
    BigInt::from_bytes_le(num_bigint::Sign::Plus, &commitment_bytes)
}

/// Compute share encryption commitment from message polynomial.
///
/// Matches the Noir `compute_share_encryption_commitment_from_message` function (raw Poseidon2).
///
/// # Arguments
/// * `message` - Message polynomial
/// * `bit_msg` - The bit width for message coefficient bounds
///
/// # Returns
/// A `BigInt` representing the commitment hash value
pub fn compute_share_encryption_commitment_from_message(
    message: &Polynomial,
    bit_msg: u32,
) -> BigInt {
    let mut payload = Vec::new();
    payload = flatten(payload, from_ref(message), bit_msg);

    let commitment_field = poseidon2_hash(&payload, &DS_SHARE_ENCRYPTION);
    let commitment_bytes = commitment_field.into_bigint().to_bytes_le();
    BigInt::from_bytes_le(num_bigint::Sign::Plus, &commitment_bytes)
}

/// Compute share encryption commitment from shares.
///
/// Matches the Noir `compute_share_encryption_commitment_from_shares` function (raw Poseidon2).
///
/// # Arguments
/// * `y` - 3D array of share values: `y[coeff_idx][mod_idx][party_idx]`
/// * `party_idx` - Index of the party (0-based)
/// * `mod_idx` - Index of the modulus
///
/// # Returns
/// A `BigInt` representing the commitment hash value
pub fn compute_share_encryption_commitment_from_shares(
    y: &[Vec<Vec<BigInt>>],
    party_idx: usize,
    mod_idx: usize,
) -> BigInt {
    let mut payload = Vec::new();

    // Add shares y[coeff_idx][mod_idx][party_idx + 1] for each coefficient
    for coeff_y in y {
        let share_value = coeff_y.get(mod_idx).expect("Modulus index out of bounds");
        let share_value = share_value
            .get(party_idx + 1)
            .expect("Party index out of bounds");
        payload.push(crate::utils::bigint_to_field(share_value));
    }

    // Include party_idx and mod_idx in the hash
    payload.push(Field::from(party_idx as u64));
    payload.push(Field::from(mod_idx as u64));

    let commitment_field = poseidon2_hash(&payload, &DS_SHARE_ENCRYPTION);
    let commitment_bytes = commitment_field.into_bigint().to_bytes_le();
    BigInt::from_bytes_le(num_bigint::Sign::Plus, &commitment_bytes)
}

/// Compute threshold public key aggregation commitment.
///
/// Matches the Noir `compute_pk_aggregation_commitment` function (raw Poseidon2):
/// commits pk0 and pk1 separately, then hashes the two commitments together.
///
/// # Arguments
/// * `pk0` - First component of the threshold public key (CRT limbs)
/// * `pk1` - Second component of the threshold public key (CRT limbs)
/// * `bit_pk` - The bit width for threshold public key coefficient bounds
///
/// # Returns
/// A `BigInt` representing the commitment hash value
pub fn compute_pk_aggregation_commitment(
    pk0: &CrtPolynomial,
    pk1: &CrtPolynomial,
    bit_pk: u32,
) -> BigInt {
    let payload0 = flatten(Vec::new(), &pk0.limbs, bit_pk);
    let commit_pk0 = poseidon2_hash(&payload0, &DS_PK_AGGREGATION);

    let payload1 = flatten(Vec::new(), &pk1.limbs, bit_pk);
    let commit_pk1 = poseidon2_hash(&payload1, &DS_PK_AGGREGATION);

    let commitment_field = poseidon2_hash(&[commit_pk0, commit_pk1], &DS_PK_AGGREGATION);
    let commitment_bytes = commitment_field.into_bigint().to_bytes_le();

    BigInt::from_bytes_le(num_bigint::Sign::Plus, &commitment_bytes)
}

/// Compute aggregation commitment.
///
/// Matches the Noir `compute_recursive_aggregation_commitment` function (raw Poseidon2).
///
/// # Arguments
/// * `payload` - Prepared payload as a vector of field elements
///
/// # Returns
/// A `BigInt` representing the commitment hash value
pub fn compute_recursive_aggregation_commitment(payload: Vec<Field>) -> BigInt {
    let commitment_field = poseidon2_hash(&payload, &DS_RECURSIVE_AGGREGATION);
    let commitment_bytes = commitment_field.into_bigint().to_bytes_le();
    BigInt::from_bytes_le(num_bigint::Sign::Plus, &commitment_bytes)
}

/// Compute CRISP ciphertext commitment.
///
/// Matches the Noir `compute_ciphertext_commitment` exactly (raw Poseidon2):
/// commits ct0 and ct1 separately, then hashes the two commitments together.
///
/// # Arguments
/// * `ct0` - First component of the ciphertext (CRT limbs)
/// * `ct1` - Second component of the ciphertext (CRT limbs)
/// * `bit_ct` - The bit width for ciphertext coefficient bounds
///
/// # Returns
/// A `BigInt` representing the commitment hash value
pub fn compute_ciphertext_commitment(
    ct0: &CrtPolynomial,
    ct1: &CrtPolynomial,
    bit_ct: u32,
) -> BigInt {
    let payload0 = flatten(Vec::new(), &ct0.limbs, bit_ct);
    let commit_ct0 = poseidon2_hash(&payload0, &DS_CIPHERTEXT);

    let payload1 = flatten(Vec::new(), &ct1.limbs, bit_ct);
    let commit_ct1 = poseidon2_hash(&payload1, &DS_CIPHERTEXT);

    let commitment_field = poseidon2_hash(&[commit_ct0, commit_ct1], &DS_CIPHERTEXT);
    let commitment_bytes = commitment_field.into_bigint().to_bytes_le();

    BigInt::from_bytes_le(num_bigint::Sign::Plus, &commitment_bytes)
}

/// Compute aggregated shares commitment (either sk_shares or e_sm_shares).
///
/// Matches the Noir `compute_aggregated_shares_commitment` function (raw Poseidon2).
///
/// # Arguments
/// * `agg_shares` - Aggregated share polynomial (CRT limbs)
/// * `bit_msg` - The bit width for message coefficient bounds
///
/// # Returns
/// A `BigInt` representing the commitment hash value
pub fn compute_aggregated_shares_commitment(agg_shares: &CrtPolynomial, bit_msg: u32) -> BigInt {
    let mut payload = Vec::new();
    payload = flatten(payload, &agg_shares.limbs, bit_msg);

    let commitment_field = poseidon2_hash(&payload, &DS_AGGREGATED_SHARES);
    let commitment_bytes = commitment_field.into_bigint().to_bytes_le();
    BigInt::from_bytes_le(num_bigint::Sign::Plus, &commitment_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::bigint_to_field;
    use e3_polynomial::CrtPolynomial;

    #[test]
    fn poseidon2_hash_deterministic() {
        let inputs = vec![Field::from(1u64), Field::from(2u64), Field::from(3u64)];
        let ds: [u8; 64] = [
            0x41, 0x42, 0x43, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let h1 = poseidon2_hash(&inputs, &ds);
        let h2 = poseidon2_hash(&inputs, &ds);
        assert_eq!(h1, h2);
        assert_ne!(h1, Field::from(0u64));
    }

    #[test]
    fn poseidon2_hash_domain_separation() {
        let inputs = vec![Field::from(1u64), Field::from(2u64)];

        let h1 = poseidon2_hash(&inputs, &DS_PK);
        let h2 = poseidon2_hash(&inputs, &DS_PK_GENERATION);
        assert_ne!(
            h1, h2,
            "Different domain separators must produce different outputs"
        );
    }

    #[test]
    fn poseidon2_hash_empty_input() {
        let inputs: Vec<Field> = vec![];
        let h = poseidon2_hash(&inputs, &DS_PK);
        assert_ne!(h, Field::from(0u64));
    }

    #[test]
    fn poseidon2_hash_single_input() {
        let inputs = vec![Field::from(42u64)];
        let h = poseidon2_hash(&inputs, &DS_PK);
        assert_ne!(h, Field::from(0u64));
    }

    #[test]
    fn poseidon2_hash_large_input() {
        // Test with more than 3 inputs (triggers multiple permutations)
        let inputs: Vec<Field> = (0..10).map(|i| Field::from(i as u64)).collect();
        let h = poseidon2_hash(&inputs, &DS_PK);
        assert_ne!(h, Field::from(0u64));
    }

    #[test]
    fn compute_ciphertext_commitment_matches_manual_payload() {
        let bit_ct = 4;
        let ct0 = CrtPolynomial::from_bigint_vectors(vec![vec![BigInt::from(1), BigInt::from(2)]]);
        let ct1 = CrtPolynomial::from_bigint_vectors(vec![vec![BigInt::from(3), BigInt::from(4)]]);

        let payload0 = flatten(Vec::new(), &ct0.limbs, bit_ct);
        let commit_ct0 = poseidon2_hash(&payload0, &DS_CIPHERTEXT);

        let payload1 = flatten(Vec::new(), &ct1.limbs, bit_ct);
        let commit_ct1 = poseidon2_hash(&payload1, &DS_CIPHERTEXT);

        let expected_field = poseidon2_hash(&[commit_ct0, commit_ct1], &DS_CIPHERTEXT);
        let expected_bytes = expected_field.into_bigint().to_bytes_le();
        let expected = BigInt::from_bytes_le(num_bigint::Sign::Plus, &expected_bytes);

        let actual = compute_ciphertext_commitment(&ct0, &ct1, bit_ct);
        assert_eq!(actual, expected);
    }

    #[test]
    fn compute_share_encryption_commitment_from_shares_matches_manual_payload() {
        let y = vec![
            vec![
                vec![BigInt::from(0), BigInt::from(11), BigInt::from(12)],
                vec![BigInt::from(0), BigInt::from(21), BigInt::from(22)],
            ],
            vec![
                vec![BigInt::from(0), BigInt::from(13), BigInt::from(14)],
                vec![BigInt::from(0), BigInt::from(23), BigInt::from(24)],
            ],
            vec![
                vec![BigInt::from(0), BigInt::from(15), BigInt::from(16)],
                vec![BigInt::from(0), BigInt::from(25), BigInt::from(26)],
            ],
        ];
        let party_idx = 0;
        let mod_idx = 1;

        let mut payload = Vec::new();
        for coeff_y in &y {
            let share_value = &coeff_y[mod_idx][party_idx + 1];
            payload.push(bigint_to_field(share_value));
        }
        payload.push(Field::from(party_idx as u64));
        payload.push(Field::from(mod_idx as u64));

        let expected_field = poseidon2_hash(&payload, &DS_SHARE_ENCRYPTION);
        let expected_bytes = expected_field.into_bigint().to_bytes_le();
        let expected = BigInt::from_bytes_le(num_bigint::Sign::Plus, &expected_bytes);

        let actual = compute_share_encryption_commitment_from_shares(&y, party_idx, mod_idx);
        assert_eq!(actual, expected);
    }

    #[test]
    fn compute_recursive_aggregation_commitment_matches_manual_payload() {
        let payload = vec![Field::from(1u64), Field::from(2u64)];

        let expected_field = poseidon2_hash(&payload, &DS_RECURSIVE_AGGREGATION);
        let expected_bytes = expected_field.into_bigint().to_bytes_le();
        let expected = BigInt::from_bytes_le(num_bigint::Sign::Plus, &expected_bytes);

        let actual = compute_recursive_aggregation_commitment(payload);
        assert_eq!(actual, expected);
    }
}
