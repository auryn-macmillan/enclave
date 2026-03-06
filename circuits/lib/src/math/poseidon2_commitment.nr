// SPDX-License-Identifier: LGPL-3.0-only
//
// Lightweight Poseidon2 commitment functions for cross-circuit data binding.
//
// These replace the SAFE sponge (Poseidon2 + Keccak-256 tag) with raw Poseidon2
// hashing. The Keccak tag (~150K constraints per sponge instance) is eliminated.
// Domain separation is achieved by encoding the domain separator string as a
// Field element prefix, costing only 1 extra field absorption (~33 constraints).
//
// IMPORTANT: These functions produce DIFFERENT outputs from the SAFE sponge
// variants in commitments.nr. All producers and consumers of a commitment value
// must be updated together.

use crate::math::helpers::flatten;
use crate::math::polynomial::Polynomial;

// Re-export domain separators from commitments.nr for convenience.
// All circuit files should import from poseidon2_commitment instead of commitments
// to ensure they use the lightweight raw Poseidon2 functions.
pub use crate::math::commitments::{
    DS_PK, DS_PK_GENERATION, DS_SHARE_COMPUTATION, DS_SHARE_ENCRYPTION,
    DS_PK_AGGREGATION, DS_CIPHERTEXT, DS_AGGREGATED_SHARES,
    DS_VK_HASH, DS_RECURSIVE_AGGREGATION, DS_USER_DATA_ENCRYPTION_COMMITMENT,
};

/// Domain separator encoding: convert a 64-byte domain separator to a Field
/// element by interpreting the first 31 bytes as a big-endian integer.
/// This preserves uniqueness for all domain separators used in Enclave
/// (all are <= 31 ASCII bytes, zero-padded to 64).
fn domain_separator_to_field(ds: [u8; 64]) -> Field {
    let mut result: Field = 0;
    for i in 0..31 {
        result = result * 256 + ds[i] as Field;
    }
    result
}

/// Raw Poseidon2 sponge hash over a variable-length vector of Fields.
///
/// Uses the standard Poseidon2 sponge construction (rate=3, capacity=1)
/// with IV = message_length * 2^64 (matching noir_stdlib's Poseidon2).
///
/// Domain separation is achieved by prepending the domain separator as
/// the first absorbed element, which is included in the message length.
pub fn poseidon2_hash(inputs: [Field], domain_separator: [u8; 64]) -> Field {
    let ds_field = domain_separator_to_field(domain_separator);
    let total_len = inputs.len() + 1; // +1 for domain separator prefix

    // IV encodes the message length (matches noir_stdlib Poseidon2 convention)
    let two_pow_64: Field = 18446744073709551616;
    let iv = (total_len as Field) * two_pow_64;

    // Initialize sponge state: [0, 0, 0, iv]
    let mut state: [Field; 4] = [0, 0, 0, iv];
    let mut cache: [Field; 3] = [0; 3];
    let mut cache_size: u32 = 0;

    // Absorb domain separator prefix
    cache[0] = ds_field;
    cache_size = 1;

    // Absorb all input elements
    for i in 0..inputs.len() {
        if cache_size == 3 {
            // Cache full - add to state and permute
            state[0] += cache[0];
            state[1] += cache[1];
            state[2] += cache[2];
            state = std::hash::poseidon2_permutation(state, 4);
            cache[0] = inputs[i];
            cache_size = 1;
        } else {
            cache[cache_size] = inputs[i];
            cache_size += 1;
        }
    }

    // Final squeeze: add remaining cache to state and permute
    for j in 0..3 {
        if j < cache_size {
            state[j] += cache[j];
        }
    }
    state = std::hash::poseidon2_permutation(state, 4);

    // Return first element of permuted state
    state[0]
}

// ============================================================================
// Drop-in replacement commitment functions
// ============================================================================

/// Generic commitment: hash a vector of Fields with a domain separator.
/// Replaces `compute_commitment()` from commitments.nr.
pub fn compute_commitment(inputs: [Field], domain_separator: [u8; 64]) -> Field {
    poseidon2_hash(inputs, domain_separator)
}

/// Single polynomial commitment: pack and hash one polynomial.
pub fn compute_single_polynomial_commitment<let N: u32, let BIT: u32>(
    polynomial: Polynomial<N>,
    domain_separator: [u8; 64],
) -> Field {
    let payload = flatten::<_, _, BIT>([].as_vector(), [polynomial]);
    compute_commitment(payload, domain_separator)
}

/// Multiple polynomial commitment: pack and hash an array of polynomials.
pub fn compute_multiple_polynomial_commitment<let N: u32, let L: u32, let BIT: u32>(
    polynomials: [Polynomial<N>; L],
    domain_separator: [u8; 64],
) -> Field {
    let payload = flatten::<_, _, BIT>([].as_vector(), polynomials);
    compute_commitment(payload, domain_separator)
}

// ============================================================================
// Domain-specific commitment functions (same signatures as commitments.nr)
// ============================================================================

pub fn compute_dkg_pk_commitment<let N: u32, let L: u32, let BIT_PK: u32>(
    pk0: [Polynomial<N>; L],
    pk1: [Polynomial<N>; L],
) -> Field {
    let mut payload = flatten::<_, _, BIT_PK>([].as_vector(), pk0);
    payload = flatten::<_, _, BIT_PK>(payload, pk1);
    compute_commitment(payload, DS_PK)
}

pub fn compute_threshold_pk_commitment<let N: u32, let L: u32, let BIT_PK: u32>(
    pk0: [Polynomial<N>; L],
    pk1: [Polynomial<N>; L],
) -> Field {
    let mut payload = flatten::<_, _, BIT_PK>([].as_vector(), pk0);
    payload = flatten::<_, _, BIT_PK>(payload, pk1);
    compute_commitment(payload, DS_PK_GENERATION)
}

pub fn compute_share_computation_sk_commitment<let N: u32, let BIT_SK: u32>(
    sk: Polynomial<N>,
) -> Field {
    let payload = flatten::<_, _, BIT_SK>([].as_vector(), [sk]);
    compute_commitment(payload, DS_SHARE_COMPUTATION)
}

pub fn compute_share_computation_e_sm_commitment<let N: u32, let L: u32, let BIT_E_SM: u32>(
    e_sm: [Polynomial<N>; L],
) -> Field {
    let payload = flatten::<_, _, BIT_E_SM>([].as_vector(), e_sm);
    compute_commitment(payload, DS_SHARE_COMPUTATION)
}

pub fn compute_share_encryption_commitment_from_message<let N: u32, let BIT_MSG: u32>(
    message: Polynomial<N>,
) -> Field {
    let payload = flatten::<_, _, BIT_MSG>([].as_vector(), [message]);
    compute_commitment(payload, DS_SHARE_ENCRYPTION)
}

pub fn compute_share_encryption_commitment_from_shares<let N: u32, let L: u32, let N_PARTIES: u32>(
    y: [[[Field; N_PARTIES + 1]; L]; N],
    party_idx: u32,
    mod_idx: u32,
) -> Field {
    let mut payload: [Field] = [].as_vector();
    for coeff_idx in 0..N {
        payload = payload.push_back(y[coeff_idx][mod_idx][party_idx + 1]);
    }
    payload = payload.push_back(party_idx as Field);
    payload = payload.push_back(mod_idx as Field);
    compute_commitment(payload, DS_SHARE_ENCRYPTION)
}

pub fn compute_aggregated_shares_commitment<let N: u32, let L: u32, let BIT_MSG: u32>(
    agg_shares: [Polynomial<N>; L],
) -> Field {
    let payload = flatten::<_, _, BIT_MSG>([].as_vector(), agg_shares);
    compute_commitment(payload, DS_AGGREGATED_SHARES)
}

pub fn compute_pk_aggregation_commitment<let N: u32, let L: u32, let BIT_PK: u32>(
    pk0: [Polynomial<N>; L],
    pk1: [Polynomial<N>; L],
) -> Field {
    let commit_pk0 = compute_multiple_polynomial_commitment::<N, L, BIT_PK>(pk0, DS_PK_AGGREGATION);
    let commit_pk1 = compute_multiple_polynomial_commitment::<N, L, BIT_PK>(pk1, DS_PK_AGGREGATION);

    let inputs = [commit_pk0, commit_pk1].as_vector();
    compute_commitment(inputs, DS_PK_AGGREGATION)
}

pub fn compute_recursive_aggregation_commitment(payload: [Field]) -> Field {
    compute_commitment(payload, DS_RECURSIVE_AGGREGATION)
}

pub fn compute_vk_hash(vk_hashes: [Field]) -> Field {
    compute_commitment(vk_hashes, DS_VK_HASH)
}

pub fn compute_ciphertext_commitment<let N: u32, let L: u32, let BIT_CT: u32>(
    ct0: [Polynomial<N>; L],
    ct1: [Polynomial<N>; L],
) -> Field {
    let commit_ct0 = compute_multiple_polynomial_commitment::<N, L, BIT_CT>(ct0, DS_CIPHERTEXT);
    let commit_ct1 = compute_multiple_polynomial_commitment::<N, L, BIT_CT>(ct1, DS_CIPHERTEXT);

    let inputs = [commit_ct0, commit_ct1].as_vector();
    compute_commitment(inputs, DS_CIPHERTEXT)
}
