// SPDX-License-Identifier: LGPL-3.0-only
//
//! # Uniform-Price Batch Auction — Threshold FHE Library
//!
//! A sealed-bid **uniform-price** batch auction built on threshold BFV
//! fully-homomorphic encryption with SIMD bit-decomposed demand encoding.
//!
//! ## Committee & Key Generation
//!
//! This example reuses the **2-of-3 committee** distributed key generation
//! (DKG), distributed eval-key MPC, and threshold decryption infrastructure
//! from the bit-plane Vickrey demo.  No trusted dealer is introduced and the
//! joint BFV secret key is never reconstructed.
//!
//! ## Encoding
//!
//! Each bidder encodes their `(quantity, price)` pair as a SIMD-packed
//! **cumulative demand vector** over a public ascending price ladder.  Each
//! logical price level occupies `SLOT_WIDTH` consecutive SIMD slots
//! containing a bit decomposition of the bidder quantity.  Uses
//! `Encoding::simd()` so that multiplication is slot-wise (Hadamard),
//! enabling plaintext-mask extraction for privacy-preserving slot isolation.
//!
//! ## Demand Accumulation (FHE Phase — Depth 0)
//!
//! Each bidder encrypts exactly one cumulative-demand plaintext with the
//! joint public key.  The aggregator computes the encrypted aggregate demand
//! curve via slot-wise ciphertext addition only:
//!
//! ```text
//!   V = Σ_i v_i
//! ```
//!
//! This consumes **no multiplicative depth** and requires no rotations for
//! the core auction computation.
//!
//! ## Clearing & Allocation (Plaintext Phase)
//!
//! After threshold-decrypting the aggregate demand vector, the committee
//! searches the decrypted demand curve from the highest price down to find
//! the clearing price.  Strict winners are fully filled; bidders exactly at
//! the clearing price share the remaining supply via deterministic
//! **largest-remainder rounding** with lower bidder index as the tiebreak.
//!
//! ## Privacy Surface
//!
//! The core auction reveals only the aggregate demand curve needed to derive
//! the clearing price.  Per-bidder allocations are extracted by multiplying
//! each bidder ciphertext with a plaintext mask that has 1s at the target slot
//! range and 0s elsewhere, then threshold-decrypting the masked result. Only
//! the isolated slot values are revealed, not the bidder's full demand vector.

pub use auction_bitplane_example::{
    aggregate_public_key, aggregate_sk_shares_for_party, build_eval_key_from_committee,
    build_params, compute_decryption_shares, generate_crp, generate_eval_key_root_seed,
    generate_smudging_noise, member_keygen, threshold_decrypt, MemberKeygenOutput, BID_BITS,
    COMMITTEE_N, SLOTS, SMUDGING_LAMBDA,
};

use fhe::bfv::{BfvParameters, Ciphertext, Encoding, Plaintext, PublicKey};
use fhe_traits::{FheEncoder, FheEncrypter};
use rand::rngs::OsRng;
use std::cmp::Reverse;
use std::sync::Arc;

/// Number of discrete price levels in the public ladder.
pub const PRICE_LEVELS: usize = 64;

/// Number of SIMD slots used per logical price level (bit-decomposed quantity).
pub const SLOT_WIDTH: usize = 16;

/// Build an ascending public price ladder with `levels` evenly-spaced values.
///
/// The first level is `min_price`; the last is `max_price`.  Intermediate
/// levels use integer interpolation over the inclusive range.
pub fn build_price_ladder(min_price: u64, max_price: u64, levels: usize) -> Vec<u64> {
    assert!(levels >= 2, "price ladder requires at least 2 levels");
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

/// Encode one bidder's `(quantity, price)` pair as a cumulative demand vector.
///
/// Each logical price level `p` spans `SLOT_WIDTH` consecutive SIMD slots.
/// When `price_ladder[p] <= price`, those slots store the bit
/// decomposition of `qty`; otherwise the whole block is zero-filled.
pub fn encode_demand_vector(
    qty: u64,
    price: u64,
    price_ladder: &[u64],
    params: &Arc<BfvParameters>,
) -> Plaintext {
    assert!(
        price_ladder.len() * SLOT_WIDTH <= params.degree(),
        "price ladder × SLOT_WIDTH exceeds polynomial degree"
    );

    let mut slots = vec![0u64; params.degree()];
    for (level_idx, &ladder_price) in price_ladder.iter().enumerate() {
        if ladder_price <= price {
            for bit in 0..SLOT_WIDTH {
                slots[level_idx * SLOT_WIDTH + bit] = ((qty >> bit) & 1) as u64;
            }
        }
    }

    Plaintext::try_encode(&slots, Encoding::simd(), params).expect("encode demand vector")
}

/// Encrypt a cumulative-demand plaintext with the joint public key.
pub fn encrypt_demand(pt: &Plaintext, pk: &PublicKey) -> Ciphertext {
    pk.try_encrypt(pt, &mut OsRng).expect("encrypt demand")
}

/// Add one bidder's encrypted demand into the running global demand curve.
pub fn accumulate_demand(global: &mut Ciphertext, contribution: &Ciphertext) {
    *global = &*global + contribution;
}

/// Build a SIMD mask plaintext with 1s at the specified price-level slot blocks.
///
/// For each level index in `target_levels`, the `SLOT_WIDTH` consecutive SIMD
/// slots are set to 1.  All other slots are zero.
pub fn build_extraction_mask(target_levels: &[usize], params: &Arc<BfvParameters>) -> Plaintext {
    let mut slots = vec![0u64; params.degree()];
    for &level in target_levels {
        for bit in 0..SLOT_WIDTH {
            slots[level * SLOT_WIDTH + bit] = 1;
        }
    }
    Plaintext::try_encode(&slots, Encoding::simd(), params).expect("encode extraction mask")
}

pub fn mask_multiply(mask: &Plaintext, target: &Ciphertext) -> Ciphertext {
    target * mask
}

/// Find the clearing price by scanning the demand curve from high to low.
///
/// Returns the highest price index whose aggregate demand is at least the
/// public supply.  On undersupply, clears at the minimum ladder price.
pub fn find_clearing_price(
    demand_curve: &[u64],
    supply: u64,
    price_ladder: &[u64],
) -> (usize, u64) {
    assert_eq!(
        demand_curve.len(),
        price_ladder.len(),
        "demand curve / price ladder length mismatch"
    );
    assert!(!price_ladder.is_empty(), "price ladder cannot be empty");

    for idx in (0..demand_curve.len()).rev() {
        if demand_curve[idx] >= supply {
            return (idx, price_ladder[idx]);
        }
    }

    (0, price_ladder[0])
}

/// Compute final per-bidder allocations from the two slots around clearing.
///
/// Each entry in `bidder_values` is `(v_i[k], v_i[k + 1])` where `k` is the
/// clearing index.  When `k` is the final ladder index, `v_i[k + 1]` is
/// ignored and strict demand is treated as 0.
pub fn compute_allocations(
    bidder_values: &[(u64, u64)],
    clearing_idx: usize,
    supply: u64,
    demand_curve: &[u64],
) -> Vec<u64> {
    assert!(
        clearing_idx < demand_curve.len(),
        "clearing index out of range for demand curve"
    );

    if clearing_idx == 0 && demand_curve[0] < supply {
        return bidder_values
            .iter()
            .map(|&(at_clear, _)| at_clear)
            .collect();
    }

    let last_idx = demand_curve.len() - 1;
    let d_strict = if clearing_idx == last_idx {
        0
    } else {
        demand_curve[clearing_idx + 1]
    };
    let remaining_supply = supply.saturating_sub(d_strict);

    let mut allocations = vec![0u64; bidder_values.len()];
    let mut marginal_entries = Vec::new();
    let mut total_marginal = 0u64;

    for (bidder_idx, &(at_clear, above_clear)) in bidder_values.iter().enumerate() {
        let strict_fill = if clearing_idx == last_idx {
            0
        } else {
            above_clear
        };
        let marginal_qty = if clearing_idx == last_idx {
            at_clear
        } else {
            at_clear
                .checked_sub(above_clear)
                .expect("bidder demand must be non-increasing across price ladder")
        };

        allocations[bidder_idx] = strict_fill;
        marginal_entries.push((bidder_idx, marginal_qty));
        total_marginal = total_marginal
            .checked_add(marginal_qty)
            .expect("total marginal quantity overflow");
    }

    if remaining_supply == 0 || total_marginal == 0 {
        return allocations;
    }

    let mut floor_sum = 0u64;
    let mut remainder_entries: Vec<(usize, u64, u128)> = marginal_entries
        .into_iter()
        .map(|(bidder_idx, marginal_qty)| {
            let scaled = (marginal_qty as u128) * (remaining_supply as u128);
            let floor = (scaled / total_marginal as u128) as u64;
            let remainder = scaled % total_marginal as u128;
            floor_sum += floor;
            (bidder_idx, floor, remainder)
        })
        .collect();

    let leftover = remaining_supply
        .checked_sub(floor_sum)
        .expect("floor allocations cannot exceed remaining supply");

    remainder_entries.sort_by_key(|&(bidder_idx, _, remainder)| (Reverse(remainder), bidder_idx));
    for entry in remainder_entries.iter_mut().take(leftover as usize) {
        entry.1 += 1;
    }
    remainder_entries.sort_by_key(|(bidder_idx, _, _)| *bidder_idx);

    for (bidder_idx, marginal_fill, _) in remainder_entries {
        allocations[bidder_idx] += marginal_fill;
    }

    allocations
}

/// Decode a single decrypted SIMD slot count, treating large values (> `t / 2`)
/// as zero.
///
/// BFV arithmetic is mod `t`.  A true zero can decrypt as `t − ε` due to
/// noise, so any value above `t / 2` is mapped back to 0.
pub fn decode_demand_slot(raw: u64, plaintext_modulus: u64) -> u64 {
    if raw > plaintext_modulus / 2 {
        0
    } else {
        raw
    }
}

/// Reconstruct the aggregate demand curve from decrypted SIMD slots.
///
/// Each logical price level spans `SLOT_WIDTH` consecutive SIMD slots.
/// The aggregate quantity at level `p` is `Σ_{j=0}^{SLOT_WIDTH-1} count[p*SLOT_WIDTH + j] * 2^j`.
pub fn decode_demand_curve(slots: &[u64], num_levels: usize, plaintext_modulus: u64) -> Vec<u64> {
    (0..num_levels)
        .map(|level| {
            let mut qty = 0u64;
            for bit in 0..SLOT_WIDTH {
                let raw = slots[level * SLOT_WIDTH + bit];
                let count = decode_demand_slot(raw, plaintext_modulus);
                qty += count * (1u64 << bit);
            }
            qty
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use fhe_traits::FheDecoder;

    fn decode_slots(pt: &Plaintext) -> Vec<u64> {
        Vec::<u64>::try_decode(pt, Encoding::simd()).expect("decode demand vector")
    }

    #[test]
    fn test_price_ladder_basic() {
        let ladder = build_price_ladder(100, 1000, 64);
        assert_eq!(ladder.len(), 64);
        assert_eq!(ladder[0], 100);
        assert_eq!(ladder[63], 1000);
        assert!(ladder.windows(2).all(|pair| pair[0] <= pair[1]));
    }

    #[test]
    fn test_price_ladder_small() {
        assert_eq!(build_price_ladder(7, 9, 2), vec![7, 9]);
    }

    #[test]
    fn test_encode_demand_vector_step_shape() {
        let params = build_params();
        let ladder = build_price_ladder(100, 1000, 10);
        let pt = encode_demand_vector(100, 500, &ladder, &params);
        let slots = decode_slots(&pt);

        for (idx, &level) in ladder.iter().enumerate() {
            let expected = if level <= 500 { 100 } else { 0 };
            let qty = (0..SLOT_WIDTH)
                .map(|bit| {
                    decode_demand_slot(slots[idx * SLOT_WIDTH + bit], params.plaintext())
                        * (1u64 << bit)
                })
                .sum::<u64>();
            assert_eq!(qty, expected, "level {idx} mismatch at price level {level}");
        }
        assert!(slots[ladder.len() * SLOT_WIDTH..]
            .iter()
            .all(|&value| value == 0));
    }

    #[test]
    fn test_encode_demand_vector_at_boundary() {
        let params = build_params();
        let ladder = vec![100, 200, 300, 400, 500];
        let pt = encode_demand_vector(55, 300, &ladder, &params);
        let slots = decode_slots(&pt);
        let curve: Vec<u64> = (0..ladder.len())
            .map(|level| {
                (0..SLOT_WIDTH)
                    .map(|bit| {
                        decode_demand_slot(slots[level * SLOT_WIDTH + bit], params.plaintext())
                            * (1u64 << bit)
                    })
                    .sum()
            })
            .collect();

        assert_eq!(&curve[..5], &[55, 55, 55, 0, 0]);
    }

    #[test]
    fn test_encode_demand_vector_below_min() {
        let params = build_params();
        let ladder = vec![100, 200, 300, 400];
        let pt = encode_demand_vector(25, 99, &ladder, &params);
        let slots = decode_slots(&pt);

        assert!(slots[..ladder.len() * SLOT_WIDTH]
            .iter()
            .all(|&value| value == 0));
    }

    #[test]
    fn test_clearing_price_basic() {
        let ladder = vec![100, 200, 300, 400, 500];
        let demand_curve = vec![20, 18, 12, 8, 3];
        assert_eq!(find_clearing_price(&demand_curve, 10, &ladder), (2, 300));
    }

    #[test]
    fn test_clearing_price_undersupply() {
        let ladder = vec![100, 200, 300, 400];
        let demand_curve = vec![7, 5, 2, 0];
        assert_eq!(find_clearing_price(&demand_curve, 10, &ladder), (0, 100));
    }

    #[test]
    fn test_clearing_price_exact_match() {
        let ladder = vec![100, 200, 300, 400, 500];
        let demand_curve = vec![20, 15, 10, 6, 1];
        assert_eq!(find_clearing_price(&demand_curve, 10, &ladder), (2, 300));
    }

    #[test]
    fn test_allocations_no_marginal() {
        let demand_curve = vec![20, 9, 9, 0];
        let bidder_values = vec![(5, 5), (9, 9), (0, 0)];
        let allocations = compute_allocations(&bidder_values, 1, 9, &demand_curve);

        assert_eq!(allocations, vec![5, 9, 0]);
    }

    #[test]
    fn test_allocations_all_marginal() {
        let demand_curve = vec![10, 10, 10, 10];
        let bidder_values = vec![(5, 0), (3, 0), (2, 0)];
        let allocations = compute_allocations(&bidder_values, 3, 7, &demand_curve);

        assert_eq!(allocations, vec![4, 2, 1]);
        assert_eq!(allocations.iter().sum::<u64>(), 7);
    }

    #[test]
    fn test_allocations_mixed() {
        let demand_curve = vec![15, 9, 8, 2];
        let bidder_values = vec![(4, 0), (2, 2), (0, 0), (2, 0), (0, 0)];
        let allocations = compute_allocations(&bidder_values, 2, 5, &demand_curve);

        assert_eq!(allocations, vec![2, 2, 0, 1, 0]);
        assert_eq!(allocations.iter().sum::<u64>(), 5);
    }

    #[test]
    fn test_allocations_remainder_tiebreak() {
        let demand_curve = vec![5, 2, 0];
        let bidder_values = vec![(1, 0), (1, 0), (0, 0)];
        let allocations = compute_allocations(&bidder_values, 1, 1, &demand_curve);

        assert_eq!(allocations, vec![1, 0, 0]);
    }

    #[test]
    fn test_allocations_r_zero() {
        let demand_curve = vec![12, 9, 5, 5];
        let bidder_values = vec![(4, 0), (2, 2), (3, 3), (0, 0)];
        let allocations = compute_allocations(&bidder_values, 1, 5, &demand_curve);

        assert_eq!(allocations, vec![0, 2, 3, 0]);
    }
}
