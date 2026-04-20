// SPDX-License-Identifier: LGPL-3.0-only

pub use auction_bitplane_example::{
    aggregate_public_key, aggregate_sk_shares_for_party, build_eval_key_from_committee,
    compute_decryption_shares, generate_crp, generate_eval_key_root_seed, generate_smudging_noise,
    member_keygen, threshold_decrypt, MemberKeygenOutput, COMMITTEE_N, SMUDGING_LAMBDA,
};

use fhe::bfv::{BfvParameters, BfvParametersBuilder, Ciphertext, Encoding, Plaintext, PublicKey};
use fhe_traits::{FheEncoder, FheEncrypter};
use rand::rngs::OsRng;
use std::cmp::Reverse;
use std::sync::Arc;

pub const SLOTS: usize = 8192;

pub const PRICE_LEVELS: usize = 512;

pub const SLOT_WIDTH: usize = 16;

pub fn build_params() -> Arc<BfvParameters> {
    BfvParametersBuilder::new()
        .set_degree(SLOTS)
        .set_plaintext_modulus(65537)
        .set_moduli_sizes(&[62, 62, 62])
        .build_arc()
        .expect("failed to build BFV parameters")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClearingDemandWitness {
    pub clearing_idx: usize,
    pub demand_at_clearing: u64,
    pub demand_above_clearing: u64,
    pub undersubscribed: bool,
}

impl ClearingDemandWitness {
    pub fn new(
        clearing_idx: usize,
        demand_at_clearing: u64,
        demand_above_clearing: u64,
        supply: u64,
    ) -> Self {
        assert!(
            demand_at_clearing >= demand_above_clearing,
            "aggregate demand must be non-increasing across the witness boundary"
        );

        Self {
            clearing_idx,
            demand_at_clearing,
            demand_above_clearing,
            undersubscribed: clearing_idx == 0 && demand_at_clearing < supply,
        }
    }

    pub fn needs_above_clearing_reveal(&self, price_levels: usize) -> bool {
        !self.undersubscribed
            && self.clearing_idx + 1 < price_levels
            && self.demand_above_clearing > 0
    }

    pub fn bidder_needs_at_clearing_reveal(
        &self,
        price_levels: usize,
        above_clearing: Option<u64>,
    ) -> bool {
        if !self.needs_above_clearing_reveal(price_levels) {
            return true;
        }

        matches!(above_clearing, Some(0))
    }
}

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

pub fn encrypt_demand(pt: &Plaintext, pk: &PublicKey) -> Ciphertext {
    pk.try_encrypt(pt, &mut OsRng).expect("encrypt demand")
}

pub fn accumulate_demand(global: &mut Ciphertext, contribution: &Ciphertext) {
    *global = &*global + contribution;
}

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

pub fn find_clearing_price_by_search<F>(
    price_ladder: &[u64],
    supply: u64,
    mut demand_at_level: F,
) -> (usize, u64)
where
    F: FnMut(usize) -> u64,
{
    assert!(!price_ladder.is_empty(), "price ladder cannot be empty");

    let mut lo = 0usize;
    let mut hi = price_ladder.len();

    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if demand_at_level(mid) >= supply {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }

    let clearing_idx = lo.saturating_sub(1);
    (clearing_idx, price_ladder[clearing_idx])
}

pub fn build_clearing_witness(clearing_idx: usize, demand_curve: &[u64]) -> ClearingDemandWitness {
    assert!(
        clearing_idx < demand_curve.len(),
        "clearing index out of range for demand curve"
    );

    ClearingDemandWitness::new(
        clearing_idx,
        demand_curve[clearing_idx],
        demand_curve.get(clearing_idx + 1).copied().unwrap_or(0),
        demand_curve[clearing_idx],
    )
}

pub fn build_clearing_witness_with_supply(
    clearing_idx: usize,
    demand_curve: &[u64],
    supply: u64,
) -> ClearingDemandWitness {
    assert!(
        clearing_idx < demand_curve.len(),
        "clearing index out of range for demand curve"
    );

    ClearingDemandWitness::new(
        clearing_idx,
        demand_curve[clearing_idx],
        demand_curve.get(clearing_idx + 1).copied().unwrap_or(0),
        supply,
    )
}

pub fn compute_allocations_from_witness(
    bidder_values: &[(u64, u64)],
    supply: u64,
    witness: ClearingDemandWitness,
) -> Vec<u64> {
    if witness.undersubscribed {
        return bidder_values
            .iter()
            .map(|&(at_clear, _)| at_clear)
            .collect();
    }

    let remaining_supply = supply.saturating_sub(witness.demand_above_clearing);

    let mut allocations = vec![0u64; bidder_values.len()];
    let mut marginal_entries = Vec::new();
    let mut total_marginal = 0u64;

    for (bidder_idx, &(at_clear, above_clear)) in bidder_values.iter().enumerate() {
        let strict_fill = above_clear;
        let marginal_qty = at_clear
            .checked_sub(above_clear)
            .expect("bidder demand must be non-increasing across price ladder");

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

    compute_allocations_from_witness(
        bidder_values,
        supply,
        build_clearing_witness_with_supply(clearing_idx, demand_curve, supply),
    )
}

pub fn decode_demand_slot(raw: u64, plaintext_modulus: u64) -> u64 {
    if raw > plaintext_modulus / 2 {
        0
    } else {
        raw
    }
}

pub fn decode_demand_curve(slots: &[u64], num_levels: usize, plaintext_modulus: u64) -> Vec<u64> {
    (0..num_levels)
        .map(|level| decode_level_quantity(slots, level, plaintext_modulus))
        .collect()
}

pub fn decode_level_quantity(slots: &[u64], level: usize, plaintext_modulus: u64) -> u64 {
    let mut qty = 0u64;
    for bit in 0..SLOT_WIDTH {
        let raw = slots[level * SLOT_WIDTH + bit];
        let count = decode_demand_slot(raw, plaintext_modulus);
        qty += count * (1u64 << bit);
    }
    qty
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
    fn test_clearing_price_by_search_matches_full_curve_scan() {
        let ladder = vec![100, 200, 300, 400, 500, 600];
        let demand_curve = vec![20, 18, 15, 11, 7, 1];
        let expected = find_clearing_price(&demand_curve, 10, &ladder);
        let actual = find_clearing_price_by_search(&ladder, 10, |idx| demand_curve[idx]);

        assert_eq!(actual, expected);
    }

    #[test]
    fn test_clearing_price_by_search_undersupply() {
        let ladder = vec![100, 200, 300, 400];
        let demand_curve = vec![7, 5, 2, 0];

        assert_eq!(
            find_clearing_price_by_search(&ladder, 10, |idx| demand_curve[idx]),
            (0, 100)
        );
    }

    #[test]
    fn test_clearing_witness_flags_undersupply() {
        let demand_curve = vec![7, 5, 2, 0];
        let witness = build_clearing_witness_with_supply(0, &demand_curve, 10);

        assert_eq!(witness.clearing_idx, 0);
        assert_eq!(witness.demand_at_clearing, 7);
        assert_eq!(witness.demand_above_clearing, 5);
        assert!(witness.undersubscribed);
        assert!(!witness.needs_above_clearing_reveal(demand_curve.len()));
        assert!(witness.bidder_needs_at_clearing_reveal(demand_curve.len(), None));
    }

    #[test]
    fn test_clearing_witness_gates_bidder_reveals() {
        let demand_curve = vec![20, 18, 12, 8, 3];
        let witness = build_clearing_witness_with_supply(2, &demand_curve, 10);

        assert!(!witness.undersubscribed);
        assert!(witness.needs_above_clearing_reveal(demand_curve.len()));
        assert!(!witness.bidder_needs_at_clearing_reveal(demand_curve.len(), Some(4)));
        assert!(witness.bidder_needs_at_clearing_reveal(demand_curve.len(), Some(0)));
    }

    #[test]
    fn test_clearing_witness_skips_above_reveal_when_no_strict_demand() {
        let demand_curve = vec![11, 9, 5, 0];
        let witness = build_clearing_witness_with_supply(2, &demand_curve, 3);

        assert_eq!(witness.demand_above_clearing, 0);
        assert!(!witness.needs_above_clearing_reveal(demand_curve.len()));
        assert!(witness.bidder_needs_at_clearing_reveal(demand_curve.len(), None));
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

    #[test]
    fn test_allocations_from_witness_matches_full_curve() {
        let demand_curve = vec![15, 9, 8, 2];
        let bidder_values = vec![(4, 0), (2, 2), (0, 0), (2, 0), (0, 0)];
        let expected = compute_allocations(&bidder_values, 2, 5, &demand_curve);
        let witness = build_clearing_witness_with_supply(2, &demand_curve, 5);

        assert_eq!(
            compute_allocations_from_witness(&bidder_values, 5, witness),
            expected
        );
    }
}
