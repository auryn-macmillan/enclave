// SPDX-License-Identifier: LGPL-3.0-only

pub use auction_bitplane_example::{
    aggregate_public_key, aggregate_sk_shares_for_party, build_eval_key_from_committee,
    build_params, compute_decryption_shares, generate_crp, generate_eval_key_root_seed,
    generate_smudging_noise, member_keygen, threshold_decrypt, MemberKeygenOutput, BID_BITS,
    COMMITTEE_N, SLOTS, SMUDGING_LAMBDA,
};
pub use batch_auction_uniform_example::{
    accumulate_demand, build_price_ladder, decode_demand_slot, PRICE_LEVELS,
};

use fhe::bfv::{BfvParameters, Ciphertext, Encoding, Plaintext, PublicKey};
use fhe_traits::{FheEncoder, FheEncrypter};
use rand::rngs::OsRng;
use std::cmp::Reverse;
use std::sync::Arc;

pub const SLOT_WIDTH: usize = 16;

pub fn encode_buy_demand_vector(
    qty: u64,
    max_price: u64,
    price_ladder: &[u64],
    params: &Arc<BfvParameters>,
) -> Plaintext {
    assert!(
        price_ladder.len() * SLOT_WIDTH <= params.degree(),
        "price ladder × SLOT_WIDTH exceeds polynomial degree"
    );

    let mut coeffs = vec![0u64; params.degree()];
    for (level_idx, &ladder_price) in price_ladder.iter().enumerate() {
        if ladder_price <= max_price {
            for bit in 0..SLOT_WIDTH {
                coeffs[level_idx * SLOT_WIDTH + bit] = ((qty >> bit) & 1) as u64;
            }
        }
    }

    Plaintext::try_encode(&coeffs, Encoding::poly(), params).expect("encode buy demand vector")
}

pub fn encode_sell_supply_vector(
    qty: u64,
    min_price: u64,
    price_ladder: &[u64],
    params: &Arc<BfvParameters>,
) -> Plaintext {
    assert!(
        price_ladder.len() * SLOT_WIDTH <= params.degree(),
        "price ladder × SLOT_WIDTH exceeds polynomial degree"
    );

    let mut coeffs = vec![0u64; params.degree()];
    for (level_idx, &ladder_price) in price_ladder.iter().enumerate() {
        if ladder_price >= min_price {
            for bit in 0..SLOT_WIDTH {
                coeffs[level_idx * SLOT_WIDTH + bit] = ((qty >> bit) & 1) as u64;
            }
        }
    }

    Plaintext::try_encode(&coeffs, Encoding::poly(), params).expect("encode sell supply vector")
}

pub fn decode_demand_curve(coeffs: &[u64], num_levels: usize, plaintext_modulus: u64) -> Vec<u64> {
    (0..num_levels)
        .map(|level| {
            let mut qty = 0u64;
            for bit in 0..SLOT_WIDTH {
                let raw = coeffs[level * SLOT_WIDTH + bit];
                let count = decode_demand_slot(raw, plaintext_modulus);
                qty += count * (1u64 << bit);
            }
            qty
        })
        .collect()
}

pub fn encrypt_demand(pt: &Plaintext, pk: &PublicKey) -> Ciphertext {
    pk.try_encrypt(pt, &mut OsRng).expect("encrypt demand")
}

pub fn find_two_sided_clearing_price(
    buy_demand: &[u64],
    sell_supply: &[u64],
    price_ladder: &[u64],
) -> Option<(usize, u64)> {
    assert_eq!(
        buy_demand.len(),
        price_ladder.len(),
        "buy curve / price ladder length mismatch"
    );
    assert_eq!(
        sell_supply.len(),
        price_ladder.len(),
        "sell curve / price ladder length mismatch"
    );

    for idx in (0..price_ladder.len()).rev() {
        if buy_demand[idx] >= sell_supply[idx] && sell_supply[idx] > 0 {
            return Some((idx, price_ladder[idx]));
        }
    }

    None
}

fn allocate_largest_remainder(entries: &[(usize, u64)], supply: u64) -> Vec<(usize, u64)> {
    let total: u64 = entries.iter().map(|(_, qty)| *qty).sum();
    if supply == 0 || total == 0 {
        return entries.iter().map(|&(idx, _)| (idx, 0)).collect();
    }

    let mut floor_sum = 0u64;
    let mut allocations: Vec<(usize, u64, u128)> = entries
        .iter()
        .map(|&(idx, qty)| {
            let scaled = (qty as u128) * (supply as u128);
            let floor = (scaled / total as u128) as u64;
            let remainder = scaled % total as u128;
            floor_sum += floor;
            (idx, floor, remainder)
        })
        .collect();

    let leftover = supply
        .checked_sub(floor_sum)
        .expect("floor allocations cannot exceed supply");

    allocations.sort_by_key(|&(idx, _, remainder)| (Reverse(remainder), idx));
    for entry in allocations.iter_mut().take(leftover as usize) {
        entry.1 += 1;
    }
    allocations.sort_by_key(|&(idx, _, _)| idx);

    allocations
        .into_iter()
        .map(|(idx, allocation, _)| (idx, allocation))
        .collect()
}

pub fn compute_two_sided_allocations(
    buyer_values: &[(u64, u64)],
    seller_values: &[(u64, u64)],
    clearing_idx: usize,
    buy_demand: &[u64],
    sell_supply: &[u64],
) -> (Vec<u64>, Vec<u64>) {
    assert!(
        clearing_idx < buy_demand.len(),
        "clearing index out of range for buy demand"
    );
    assert!(
        clearing_idx < sell_supply.len(),
        "clearing index out of range for sell supply"
    );

    let matched_volume = buy_demand[clearing_idx].min(sell_supply[clearing_idx]);

    let buyer_strict: Vec<u64> = buyer_values
        .iter()
        .map(|&(at_clearing, above_clearing)| {
            assert!(
                at_clearing >= above_clearing,
                "buyer value at clearing must be at least value above clearing"
            );
            above_clearing
        })
        .collect();
    let buyer_marginal: Vec<u64> = buyer_values
        .iter()
        .map(|&(at_clearing, above_clearing)| at_clearing - above_clearing)
        .collect();

    let seller_strict: Vec<u64> = seller_values
        .iter()
        .map(|&(at_clearing, below_clearing)| {
            assert!(
                at_clearing >= below_clearing,
                "seller value at clearing must be at least value below clearing"
            );
            below_clearing
        })
        .collect();
    let seller_marginal: Vec<u64> = seller_values
        .iter()
        .map(|&(at_clearing, below_clearing)| at_clearing - below_clearing)
        .collect();

    if buy_demand[clearing_idx] > sell_supply[clearing_idx] {
        let strict_buy_demand: u64 = buyer_strict.iter().sum();
        let remaining = matched_volume
            .checked_sub(strict_buy_demand)
            .expect("strict buy demand cannot exceed matched volume");

        let mut buyer_allocations = buyer_strict.clone();
        let prorated = allocate_largest_remainder(
            &buyer_marginal
                .iter()
                .enumerate()
                .map(|(idx, &qty)| (idx, qty))
                .collect::<Vec<_>>(),
            remaining,
        );
        for (idx, allocation) in prorated {
            buyer_allocations[idx] += allocation;
        }

        let seller_allocations = seller_values
            .iter()
            .map(|&(at_clearing, _)| at_clearing)
            .collect();
        return (buyer_allocations, seller_allocations);
    }

    if sell_supply[clearing_idx] > buy_demand[clearing_idx] {
        let strict_sell_supply: u64 = seller_strict.iter().sum();
        let remaining = matched_volume
            .checked_sub(strict_sell_supply)
            .expect("strict sell supply cannot exceed matched volume");

        let buyer_allocations = buyer_values
            .iter()
            .map(|&(at_clearing, _)| at_clearing)
            .collect();

        let mut seller_allocations = seller_strict.clone();
        let prorated = allocate_largest_remainder(
            &seller_marginal
                .iter()
                .enumerate()
                .map(|(idx, &qty)| (idx, qty))
                .collect::<Vec<_>>(),
            remaining,
        );
        for (idx, allocation) in prorated {
            seller_allocations[idx] += allocation;
        }

        return (buyer_allocations, seller_allocations);
    }

    (
        buyer_values
            .iter()
            .map(|&(at_clearing, _)| at_clearing)
            .collect(),
        seller_values
            .iter()
            .map(|&(at_clearing, _)| at_clearing)
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use fhe_traits::FheDecoder;

    fn decode_slots(pt: &Plaintext) -> Vec<u64> {
        Vec::<u64>::try_decode(pt, Encoding::poly()).expect("decode vector")
    }

    #[test]
    fn test_encode_buy_demand_vector() {
        let params = build_params();
        let ladder = vec![100, 200, 300, 400, 500];
        let pt = encode_buy_demand_vector(25, 300, &ladder, &params);
        let coeffs = decode_slots(&pt);

        for (level_idx, &price) in ladder.iter().enumerate() {
            let qty = (0..SLOT_WIDTH)
                .map(|bit| coeffs[level_idx * SLOT_WIDTH + bit] * (1u64 << bit))
                .sum::<u64>();
            let expected = if price <= 300 { 25 } else { 0 };
            assert_eq!(qty, expected, "unexpected qty at level {level_idx}");
        }
        assert!(coeffs[ladder.len() * SLOT_WIDTH..]
            .iter()
            .all(|&value| value == 0));
    }

    #[test]
    fn test_encode_sell_supply_vector() {
        let params = build_params();
        let ladder = vec![100, 200, 300, 400, 500];
        let pt = encode_sell_supply_vector(40, 300, &ladder, &params);
        let coeffs = decode_slots(&pt);

        for (level_idx, &price) in ladder.iter().enumerate() {
            let qty = (0..SLOT_WIDTH)
                .map(|bit| coeffs[level_idx * SLOT_WIDTH + bit] * (1u64 << bit))
                .sum::<u64>();
            let expected = if price >= 300 { 40 } else { 0 };
            assert_eq!(qty, expected, "unexpected qty at level {level_idx}");
        }
        assert!(coeffs[ladder.len() * SLOT_WIDTH..]
            .iter()
            .all(|&value| value == 0));
    }

    #[test]
    fn test_clearing_price_basic() {
        let ladder = vec![100, 200, 300, 400, 500];
        let buy = vec![15, 14, 9, 6, 0];
        let sell = vec![0, 2, 5, 10, 13];

        assert_eq!(
            find_two_sided_clearing_price(&buy, &sell, &ladder),
            Some((2, 300))
        );
    }

    #[test]
    fn test_clearing_price_no_intersection() {
        let ladder = vec![100, 200, 300];
        let buy = vec![5, 4, 3];
        let sell = vec![6, 7, 8];

        assert_eq!(find_two_sided_clearing_price(&buy, &sell, &ladder), None);
    }

    #[test]
    fn test_allocations_buy_side_rationed() {
        let buyer_values = vec![(5, 3), (4, 1), (1, 0)];
        let seller_values = vec![(2, 0), (3, 1), (3, 2)];
        let buy_demand = vec![12, 10, 4];
        let sell_supply = vec![5, 8, 8];

        let (buyer_allocations, seller_allocations) = compute_two_sided_allocations(
            &buyer_values,
            &seller_values,
            1,
            &buy_demand,
            &sell_supply,
        );

        assert_eq!(buyer_allocations, vec![4, 3, 1]);
        assert_eq!(seller_allocations, vec![2, 3, 3]);
        assert_eq!(buyer_allocations.iter().sum::<u64>(), 8);
        assert_eq!(seller_allocations.iter().sum::<u64>(), 8);
    }

    #[test]
    fn test_allocations_sell_side_rationed() {
        let buyer_values = vec![(3, 1), (3, 2), (2, 0)];
        let seller_values = vec![(5, 2), (2, 1), (3, 0)];
        let buy_demand = vec![10, 8, 3];
        let sell_supply = vec![7, 10, 10];

        let (buyer_allocations, seller_allocations) = compute_two_sided_allocations(
            &buyer_values,
            &seller_values,
            1,
            &buy_demand,
            &sell_supply,
        );

        assert_eq!(buyer_allocations, vec![3, 3, 2]);
        assert_eq!(seller_allocations, vec![4, 2, 2]);
        assert_eq!(buyer_allocations.iter().sum::<u64>(), 8);
        assert_eq!(seller_allocations.iter().sum::<u64>(), 8);
    }

    #[test]
    fn test_allocations_exact_match() {
        let buyer_values = vec![(4, 1), (5, 3)];
        let seller_values = vec![(6, 2), (3, 1)];
        let buy_demand = vec![12, 9, 4];
        let sell_supply = vec![4, 9, 9];

        let (buyer_allocations, seller_allocations) = compute_two_sided_allocations(
            &buyer_values,
            &seller_values,
            1,
            &buy_demand,
            &sell_supply,
        );

        assert_eq!(buyer_allocations, vec![4, 5]);
        assert_eq!(seller_allocations, vec![6, 3]);
        assert_eq!(buyer_allocations.iter().sum::<u64>(), 9);
        assert_eq!(seller_allocations.iter().sum::<u64>(), 9);
    }
}
