// SPDX-License-Identifier: LGPL-3.0-only
//
//! # Capped Token Sale — Threshold FHE Library
//!
//! A sealed-bid **capped token sale** built on threshold BFV fully-homomorphic
//! encryption with SIMD batching.
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
//! Each bidder encodes their `(lots, price)` pair as a SIMD **cumulative
//! demand vector** over a public ascending price ladder.  Slot `p` holds the
//! bidder's **clamped** lot request when `price_ladder[p] <= price`, and 0
//! otherwise.  The per-bidder public cap is enforced entirely at encoding
//! time: `clamped_lots = min(lots, cap_k)`.
//!
//! ## Demand Accumulation (FHE Phase — Depth 0)
//!
//! Each bidder encrypts exactly one cumulative-demand plaintext with the joint
//! public key.  The aggregator computes the encrypted aggregate demand curve
//! via slot-wise ciphertext addition only:
//!
//! ```text
//!   V = Σ_i v_i
//! ```
//!
//! This consumes **no multiplicative depth** and requires no rotations for the
//! core sale computation.
//!
//! ## Clearing, Allocation, and Settlement (Plaintext Phase)
//!
//! After threshold-decrypting the aggregate demand vector, the committee
//! searches the decrypted demand curve from the highest price down to find the
//! clearing price.  Strict winners are fully filled; bidders exactly at the
//! clearing price share the remaining supply via deterministic
//! **largest-remainder rounding** with lower bidder index as the tiebreak.
//! Payments are `clearing_price × allocated_lots × lot_size`, while refunds are
//! the unused portion of each bidder's locked collateral.
//!
//! ## Privacy Surface
//!
//! The core sale reveals only the aggregate demand curve needed to derive the
//! clearing price.  Exact per-bidder allocations can be computed from the two
//! relevant ladder slots (`k` and `k + 1`) of each bidder's masked demand
//! vector, without revealing the bidder's raw unclamped quantity.

pub use auction_bitplane_example::{
    aggregate_public_key, aggregate_sk_shares_for_party, build_eval_key_from_committee,
    build_params, compute_decryption_shares, generate_crp, generate_eval_key_root_seed,
    generate_smudging_noise, member_keygen, threshold_decrypt, MemberKeygenOutput, BID_BITS,
    COMMITTEE_N, SLOTS, SMUDGING_LAMBDA,
};

pub use batch_auction_uniform_example::{
    accumulate_demand, build_price_ladder, compute_allocations, decode_demand_curve,
    decode_demand_slot, find_clearing_price, PRICE_LEVELS, SLOT_WIDTH,
};

use batch_auction_uniform_example::encode_demand_vector;
use fhe::bfv::{BfvParameters, Ciphertext, Plaintext, PublicKey};
use fhe_traits::FheEncrypter;
use rand::rngs::OsRng;
use std::sync::Arc;

/// Public configuration for a capped token sale.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SaleConfig {
    /// Number of tokens represented by one lot.
    pub lot_size: u64,
    /// Maximum number of lots any bidder may request.
    pub cap_k: u64,
    /// Total token-sale supply, denominated in lots.
    pub total_supply_lots: u64,
    /// Public ascending price ladder used for cumulative-demand encoding.
    pub price_ladder: Vec<u64>,
}

fn clamp_lots(lots: u64, config: &SaleConfig) -> u64 {
    lots.min(config.cap_k)
}

/// Encode one bidder's capped `(lots, price)` pair as a cumulative demand vector.
///
/// The requested `lots` are clamped to `min(lots, config.cap_k)` before the
/// same step-function encoding used by the uniform-price batch auction.
pub fn encode_capped_demand_vector(
    lots: u64,
    price: u64,
    config: &SaleConfig,
    params: &Arc<BfvParameters>,
) -> Plaintext {
    encode_demand_vector(
        clamp_lots(lots, config),
        price,
        &config.price_ladder,
        params,
    )
}

/// Encrypt a capped demand plaintext with the joint public key.
pub fn encrypt_demand(pt: &Plaintext, pk: &PublicKey) -> Ciphertext {
    pk.try_encrypt(pt, &mut OsRng).expect("encrypt demand")
}

/// Compute the final payment in token units of account.
///
/// Returns `clearing_price × allocated_lots × lot_size`.
pub fn compute_payment(clearing_price: u64, allocated_lots: u64, lot_size: u64) -> u64 {
    ((clearing_price as u128) * (allocated_lots as u128) * (lot_size as u128))
        .try_into()
        .expect("payment overflow")
}

/// Compute the collateral locked at bid submission time.
///
/// Returns `max_price × requested_lots × lot_size`, where `requested_lots`
/// must already be clamped.
pub fn compute_collateral(max_price: u64, requested_lots: u64, lot_size: u64) -> u64 {
    ((max_price as u128) * (requested_lots as u128) * (lot_size as u128))
        .try_into()
        .expect("collateral overflow")
}

/// Compute the bidder refund after settlement.
///
/// Returns `collateral - payment`, saturating at 0.
pub fn compute_refund(collateral: u64, payment: u64) -> u64 {
    collateral.saturating_sub(payment)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fhe::bfv::Encoding;
    use fhe_traits::FheDecoder;

    fn test_config(price_ladder: Vec<u64>, cap_k: u64, total_supply_lots: u64) -> SaleConfig {
        SaleConfig {
            lot_size: 100,
            cap_k,
            total_supply_lots,
            price_ladder,
        }
    }

    fn decode_coeffs(pt: &Plaintext) -> Vec<u64> {
        Vec::<u64>::try_decode(pt, Encoding::poly()).expect("decode demand vector")
    }

    fn reconstruct_qty(coeffs: &[u64], level_idx: usize) -> u64 {
        let slot_width = 16usize;
        (0..slot_width)
            .map(|bit| coeffs[level_idx * slot_width + bit] * (1u64 << bit))
            .sum()
    }

    fn aggregate_curve(
        bids: &[(u64, u64)],
        config: &SaleConfig,
        params: &Arc<BfvParameters>,
    ) -> Vec<u64> {
        let mut aggregate = vec![0u64; config.price_ladder.len()];

        for &(lots, price) in bids {
            let pt = encode_capped_demand_vector(lots, price, config, params);
            let coeffs = decode_coeffs(&pt);
            for (idx, value) in aggregate.iter_mut().enumerate() {
                *value += reconstruct_qty(&coeffs, idx);
            }
        }

        aggregate
    }

    fn bidder_values_at_clear(
        bids: &[(u64, u64)],
        clearing_idx: usize,
        config: &SaleConfig,
        params: &Arc<BfvParameters>,
    ) -> Vec<(u64, u64)> {
        bids.iter()
            .map(|&(lots, price)| {
                let pt = encode_capped_demand_vector(lots, price, config, params);
                let coeffs = decode_coeffs(&pt);
                let at_clear = reconstruct_qty(&coeffs, clearing_idx);
                let above_clear = if clearing_idx + 1 < config.price_ladder.len() {
                    reconstruct_qty(&coeffs, clearing_idx + 1)
                } else {
                    0
                };
                (at_clear, above_clear)
            })
            .collect()
    }

    #[test]
    fn test_encode_capped_demand_below_cap() {
        let params = build_params();
        let config = test_config(vec![100, 200, 300, 400, 500], 500, 1_000);
        let pt = encode_capped_demand_vector(300, 300, &config, &params);
        let coeffs = decode_coeffs(&pt);

        let quantities: Vec<u64> = (0..config.price_ladder.len())
            .map(|idx| reconstruct_qty(&coeffs, idx))
            .collect();
        assert_eq!(&quantities[..5], &[300, 300, 300, 0, 0]);
    }

    #[test]
    fn test_encode_capped_demand_at_cap() {
        let params = build_params();
        let config = test_config(vec![100, 200, 300, 400, 500], 500, 1_000);
        let pt = encode_capped_demand_vector(500, 400, &config, &params);
        let coeffs = decode_coeffs(&pt);

        let quantities: Vec<u64> = (0..config.price_ladder.len())
            .map(|idx| reconstruct_qty(&coeffs, idx))
            .collect();
        assert_eq!(&quantities[..5], &[500, 500, 500, 500, 0]);
    }

    #[test]
    fn test_encode_capped_demand_above_cap() {
        let params = build_params();
        let config = test_config(vec![100, 200, 300, 400, 500], 500, 1_000);
        let pt = encode_capped_demand_vector(1_000, 500, &config, &params);
        let coeffs = decode_coeffs(&pt);

        let quantities: Vec<u64> = (0..config.price_ladder.len())
            .map(|idx| reconstruct_qty(&coeffs, idx))
            .collect();
        assert_eq!(&quantities[..5], &[500, 500, 500, 500, 500]);
    }

    #[test]
    fn test_encode_capped_demand_zero() {
        let params = build_params();
        let config = test_config(vec![100, 200, 300, 400, 500], 500, 1_000);
        let pt = encode_capped_demand_vector(0, 500, &config, &params);
        let coeffs = decode_coeffs(&pt);

        assert!(coeffs[..config.price_ladder.len() * 16]
            .iter()
            .all(|&value| value == 0));
    }

    #[test]
    fn test_payment_computation() {
        assert_eq!(compute_payment(300, 5, 100), 150_000);
    }

    #[test]
    fn test_refund_computation() {
        assert_eq!(compute_refund(200_000, 150_000), 50_000);
    }

    #[test]
    fn test_refund_computation_saturating() {
        assert_eq!(compute_refund(100_000, 150_000), 0);
    }

    #[test]
    fn test_collateral_computation() {
        assert_eq!(compute_collateral(400, 5, 100), 200_000);
    }

    #[test]
    fn test_clearing_with_capped_demand() {
        let params = build_params();
        let config = test_config(vec![100, 200, 300, 400], 500, 800);
        let bids = vec![(1_000, 400), (250, 300), (100, 100)];

        let demand_curve = aggregate_curve(&bids, &config, &params);
        assert_eq!(demand_curve, vec![850, 750, 750, 500]);

        let (clearing_idx, clearing_price) = find_clearing_price(
            &demand_curve,
            config.total_supply_lots,
            &config.price_ladder,
        );
        assert_eq!((clearing_idx, clearing_price), (0, 100));
    }

    #[test]
    fn test_undersupply_all_filled() {
        let params = build_params();
        let config = test_config(vec![100, 200, 300, 400], 500, 1_000);
        let bids = vec![(600, 400), (250, 300), (100, 200)];

        let demand_curve = aggregate_curve(&bids, &config, &params);
        let bidder_values = bidder_values_at_clear(&bids, 0, &config, &params);
        let allocations =
            compute_allocations(&bidder_values, 0, config.total_supply_lots, &demand_curve);

        assert_eq!(allocations, vec![500, 250, 100]);
    }

    #[test]
    fn test_encrypt_demand_roundtrip_shape() {
        let params = build_params();
        let config = test_config(vec![100, 200, 300, 400], 500, 500);
        let crp = generate_crp(&params);
        let members: Vec<_> = (0..COMMITTEE_N)
            .map(|_| member_keygen(&params, &crp))
            .collect();
        let pk_shares: Vec<_> = members
            .iter()
            .map(|member| member.pk_share.clone())
            .collect();
        let joint_pk = aggregate_public_key(pk_shares);
        let all_sk_shares: Vec<_> = members
            .iter()
            .map(|member| member.sk_shares.clone())
            .collect();
        let sk_poly_sums: Vec<_> = (0..COMMITTEE_N)
            .map(|i| aggregate_sk_shares_for_party(&all_sk_shares, i, &params))
            .collect();

        let pt = encode_capped_demand_vector(600, 300, &config, &params);
        let ct = encrypt_demand(&pt, &joint_pk);
        let participating = [0usize, 1];
        let party_shares: Vec<(usize, Vec<_>)> = participating
            .iter()
            .map(|&i| {
                let smudging = generate_smudging_noise(&params, 1);
                let shares = compute_decryption_shares(
                    std::slice::from_ref(&ct),
                    &sk_poly_sums[i],
                    &smudging,
                    &params,
                );
                (i + 1, shares)
            })
            .collect();

        let pts = threshold_decrypt(&party_shares, std::slice::from_ref(&ct), &params);
        let coeffs = decode_coeffs(&pts[0]);
        let quantities: Vec<u64> = (0..config.price_ladder.len())
            .map(|idx| reconstruct_qty(&coeffs, idx))
            .collect();
        assert_eq!(&quantities[..4], &[500, 500, 500, 0]);
    }

    #[test]
    fn test_payment_refund_identity() {
        let collateral = compute_collateral(700, 300, 100);
        let payment = compute_payment(500, 180, 100);
        let refund = compute_refund(collateral, payment);

        assert_eq!(refund + payment, collateral);
    }

    #[test]
    fn test_marginal_allocation_with_capped_bidder() {
        let params = build_params();
        let config = test_config(vec![100, 200, 300, 400], 500, 700);
        let bids = vec![(700, 300), (450, 300), (200, 400)];
        let demand_curve = aggregate_curve(&bids, &config, &params);
        let bidder_values = bidder_values_at_clear(&bids, 2, &config, &params);
        let allocations =
            compute_allocations(&bidder_values, 2, config.total_supply_lots, &demand_curve);

        assert_eq!(demand_curve, vec![1_150, 1_150, 1_150, 200]);
        assert_eq!(allocations, vec![263, 237, 200]);
        assert_eq!(allocations.iter().sum::<u64>(), config.total_supply_lots);
    }
}
