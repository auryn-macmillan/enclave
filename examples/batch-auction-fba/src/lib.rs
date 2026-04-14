// SPDX-License-Identifier: LGPL-3.0-only

pub use auction_bitplane_example::{
    aggregate_public_key, aggregate_sk_shares_for_party, build_eval_key_from_committee,
    build_params, compute_decryption_shares, generate_crp, generate_eval_key_root_seed,
    generate_smudging_noise, member_keygen, threshold_decrypt, MemberKeygenOutput, BID_BITS,
    COMMITTEE_N, SLOTS, SMUDGING_LAMBDA,
};
pub use batch_auction_uniform_example::{
    accumulate_demand, build_price_ladder, compute_allocations, decode_demand_slot,
    encode_demand_vector, encrypt_demand, find_clearing_price, PRICE_LEVELS,
};
pub use fhe::bfv::EvaluationKey;

use fhe::bfv::{BfvParameters, Ciphertext, Encoding, Plaintext, PublicKey};
use fhe_math::rq::Poly;
use fhe_traits::{FheDecoder, FheEncoder, FheEncrypter};
use rand::rngs::OsRng;
use std::cmp::Reverse;
use std::sync::Arc;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Order {
    pub order_id: usize,
    pub bidder_slot: usize,
    pub qty: u64,
    pub price: u64,
    pub epoch: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchState {
    pub epoch: usize,
    pub supply: u64,
    pub active_orders: Vec<Order>,
    pub price_ladder: Vec<u64>,
    next_order_id: usize,
}

impl BatchState {
    pub fn new(supply: u64, price_ladder: Vec<u64>) -> Self {
        assert!(!price_ladder.is_empty(), "price ladder cannot be empty");

        Self {
            epoch: 1,
            supply,
            active_orders: Vec::new(),
            price_ladder,
            next_order_id: 0,
        }
    }

    pub fn submit_order(&mut self, bidder_slot: usize, qty: u64, price: u64) -> usize {
        assert!(bidder_slot < SLOTS, "bidder slot exceeds SIMD capacity");
        assert!(qty > 0, "order quantity must be positive");
        assert!(
            self.price_ladder.contains(&price),
            "order price must exist on the public ladder"
        );

        let order_id = self.next_order_id;
        self.next_order_id += 1;

        self.active_orders.push(Order {
            order_id,
            bidder_slot,
            qty,
            price,
            epoch: self.epoch,
        });

        order_id
    }

    pub fn cancel_order(&mut self, order_id: usize) -> bool {
        let before = self.active_orders.len();
        self.active_orders
            .retain(|order| order.order_id != order_id);
        self.active_orders.len() != before
    }

    pub fn advance_epoch(&mut self) {
        self.epoch += 1;
    }
}

pub fn to_one_hot(
    ct: &Ciphertext,
    eval_key: &EvaluationKey,
    params: &Arc<BfvParameters>,
) -> Ciphertext {
    assert!(
        PRICE_LEVELS <= params.degree(),
        "price ladder exceeds SIMD slots"
    );

    let rotated = eval_key
        .rotates_columns_by(ct, 1)
        .expect("column rotation for one-hot transform");

    let mut zero_guard_slots = vec![0u64; params.degree()];
    for slot in zero_guard_slots
        .iter_mut()
        .take(PRICE_LEVELS.saturating_sub(1))
    {
        *slot = 1;
    }
    let zero_guard_mask =
        Plaintext::try_encode(&zero_guard_slots, Encoding::simd(), params).expect("encode mask");

    let masked_rotated = &rotated * &zero_guard_mask;
    ct - &masked_rotated
}

pub fn build_classification_masks(
    clearing_idx: usize,
    params: &Arc<BfvParameters>,
) -> (Plaintext, Plaintext, Plaintext) {
    assert!(clearing_idx < PRICE_LEVELS, "clearing index out of range");
    assert!(
        PRICE_LEVELS <= params.degree(),
        "price ladder exceeds SIMD slots"
    );

    let mut winner_slots = vec![0u64; params.degree()];
    let mut loser_slots = vec![0u64; params.degree()];
    let mut marginal_slots = vec![0u64; params.degree()];

    for slot in winner_slots
        .iter_mut()
        .take(PRICE_LEVELS)
        .skip(clearing_idx + 1)
    {
        *slot = 1;
    }
    for slot in loser_slots.iter_mut().take(clearing_idx) {
        *slot = 1;
    }
    marginal_slots[clearing_idx] = 1;

    (
        Plaintext::try_encode(&winner_slots, Encoding::simd(), params).expect("encode winner mask"),
        Plaintext::try_encode(&loser_slots, Encoding::simd(), params).expect("encode loser mask"),
        Plaintext::try_encode(&marginal_slots, Encoding::simd(), params)
            .expect("encode marginal mask"),
    )
}

pub fn apply_mask(ct: &Ciphertext, mask: &Plaintext) -> Ciphertext {
    ct * mask
}

pub fn decrypt_one_hot_slot(
    ct: &Ciphertext,
    mask: &Plaintext,
    slot_idx: usize,
    participating: &[usize],
    sk_poly_sums: &[Poly],
    params: &Arc<BfvParameters>,
) -> u64 {
    assert!(slot_idx < params.degree(), "slot index out of range");
    assert!(
        participating.iter().all(|&idx| idx < sk_poly_sums.len()),
        "participating party index out of range"
    );

    let masked_ct = apply_mask(ct, mask);
    let party_shares: Vec<(usize, Vec<_>)> = participating
        .iter()
        .map(|&i| {
            let smudging = generate_smudging_noise(params, 1);
            let shares = compute_decryption_shares(
                std::slice::from_ref(&masked_ct),
                &sk_poly_sums[i],
                &smudging,
                params,
            );
            (i + 1, shares)
        })
        .collect();

    let plaintexts = threshold_decrypt(&party_shares, std::slice::from_ref(&masked_ct), params);
    let slots = Vec::<u64>::try_decode(&plaintexts[0], Encoding::simd()).expect("decode slot");
    decode_demand_slot(slots[slot_idx], params.plaintext())
}

pub fn encrypt_one_hot_residual(
    qty: u64,
    slot_idx: usize,
    params: &Arc<BfvParameters>,
    pk: &PublicKey,
) -> Ciphertext {
    assert!(slot_idx < params.degree(), "slot index out of range");

    let mut slots = vec![0u64; params.degree()];
    slots[slot_idx] = qty;
    let plaintext =
        Plaintext::try_encode(&slots, Encoding::simd(), params).expect("encode residual");
    pk.try_encrypt(&plaintext, &mut OsRng)
        .expect("encrypt one-hot residual")
}

pub fn histogram_to_demand_curve(histogram: &[u64]) -> Vec<u64> {
    let mut demand_curve = vec![0u64; histogram.len()];
    let mut suffix = 0u64;

    for (idx, &value) in histogram.iter().enumerate().rev() {
        suffix = suffix
            .checked_add(value)
            .expect("histogram suffix-sum overflow");
        demand_curve[idx] = suffix;
    }

    demand_curve
}

pub fn accumulate_one_hot(global: &mut Ciphertext, contribution: &Ciphertext) {
    accumulate_demand(global, contribution);
}

pub fn allocate_fba(
    bids: &[Order],
    clearing_idx: usize,
    clearing_price: u64,
    supply: u64,
    demand_curve: &[u64],
) -> Vec<(usize, u64)> {
    assert!(
        clearing_idx < demand_curve.len(),
        "clearing index out of range for demand curve"
    );

    if clearing_idx == 0 && demand_curve[0] < supply {
        return bids.iter().map(|bid| (bid.order_id, bid.qty)).collect();
    }

    let last_idx = demand_curve.len() - 1;
    let d_strict = if clearing_idx == last_idx {
        0
    } else {
        demand_curve[clearing_idx + 1]
    };
    let mut remaining_supply = supply.saturating_sub(d_strict);

    let mut allocations = vec![0u64; bids.len()];
    let mut marginal_indices = Vec::new();

    for (idx, bid) in bids.iter().enumerate() {
        if bid.price > clearing_price {
            allocations[idx] = bid.qty;
        } else if bid.price == clearing_price {
            marginal_indices.push(idx);
        }
    }

    marginal_indices.sort_by_key(|&idx| (bids[idx].epoch, bids[idx].order_id));

    let mut group_start = 0usize;
    while group_start < marginal_indices.len() && remaining_supply > 0 {
        let epoch = bids[marginal_indices[group_start]].epoch;
        let mut group_end = group_start;
        let mut epoch_total = 0u64;

        while group_end < marginal_indices.len() && bids[marginal_indices[group_end]].epoch == epoch
        {
            epoch_total = epoch_total
                .checked_add(bids[marginal_indices[group_end]].qty)
                .expect("epoch marginal quantity overflow");
            group_end += 1;
        }

        if remaining_supply >= epoch_total {
            for &idx in &marginal_indices[group_start..group_end] {
                allocations[idx] = bids[idx].qty;
            }
            remaining_supply -= epoch_total;
            group_start = group_end;
            continue;
        }

        let mut floor_sum = 0u64;
        let mut remainder_entries: Vec<(usize, u64, u128)> = marginal_indices
            [group_start..group_end]
            .iter()
            .map(|&idx| {
                let scaled = (bids[idx].qty as u128) * (remaining_supply as u128);
                let floor = (scaled / epoch_total as u128) as u64;
                let remainder = scaled % epoch_total as u128;
                floor_sum += floor;
                (idx, floor, remainder)
            })
            .collect();

        let leftover = remaining_supply
            .checked_sub(floor_sum)
            .expect("floor allocations cannot exceed remaining supply");

        remainder_entries
            .sort_by_key(|&(idx, _, remainder)| (Reverse(remainder), bids[idx].order_id));
        for entry in remainder_entries.iter_mut().take(leftover as usize) {
            entry.1 += 1;
        }

        for (idx, marginal_fill, _) in remainder_entries {
            allocations[idx] = marginal_fill;
        }

        remaining_supply = 0;
    }

    bids.iter()
        .enumerate()
        .map(|(idx, bid)| (bid.order_id, allocations[idx]))
        .collect()
}

pub fn compute_residual_qty(original_qty: u64, allocated: u64) -> u64 {
    original_qty
        .checked_sub(allocated)
        .expect("allocated quantity cannot exceed original quantity")
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestFixture {
        params: Arc<BfvParameters>,
        joint_pk: PublicKey,
        sk_poly_sums: Vec<Poly>,
        eval_key: EvaluationKey,
        price_ladder: Vec<u64>,
        participating: [usize; 2],
    }

    fn test_fixture() -> TestFixture {
        let params = build_params();
        let crp = generate_crp(&params);
        let members: Vec<_> = (0..COMMITTEE_N)
            .map(|_| member_keygen(&params, &crp))
            .collect();

        let joint_pk = aggregate_public_key(
            members
                .iter()
                .map(|member| member.pk_share.clone())
                .collect(),
        );

        let all_sk_shares: Vec<_> = members
            .iter()
            .map(|member| member.sk_shares.clone())
            .collect();
        let sk_poly_sums: Vec<_> = (0..COMMITTEE_N)
            .map(|i| aggregate_sk_shares_for_party(&all_sk_shares, i, &params))
            .collect();

        let member_sk_refs: Vec<&_> = members.iter().map(|member| &member.sk).collect();
        let eval_key_root_seed = generate_eval_key_root_seed();
        let (eval_key, _) =
            build_eval_key_from_committee(&member_sk_refs, &params, &eval_key_root_seed);

        TestFixture {
            params,
            joint_pk,
            sk_poly_sums,
            eval_key,
            price_ladder: build_price_ladder(100, 1_000, PRICE_LEVELS),
            participating: [0, 1],
        }
    }

    fn decode_plaintext_slots(pt: &Plaintext) -> Vec<u64> {
        Vec::<u64>::try_decode(pt, Encoding::simd()).expect("decode plaintext")
    }

    fn threshold_decrypt_slots(
        ct: &Ciphertext,
        participating: &[usize],
        sk_poly_sums: &[Poly],
        params: &Arc<BfvParameters>,
    ) -> Vec<u64> {
        let party_shares: Vec<(usize, Vec<_>)> = participating
            .iter()
            .map(|&i| {
                let smudging = generate_smudging_noise(params, 1);
                let shares = compute_decryption_shares(
                    std::slice::from_ref(ct),
                    &sk_poly_sums[i],
                    &smudging,
                    params,
                );
                (i + 1, shares)
            })
            .collect();

        let plaintexts = threshold_decrypt(&party_shares, std::slice::from_ref(ct), params);
        decode_plaintext_slots(&plaintexts[0])
    }

    fn order(order_id: usize, qty: u64, price: u64, epoch: usize) -> Order {
        Order {
            order_id,
            bidder_slot: order_id,
            qty,
            price,
            epoch,
        }
    }

    #[test]
    fn test_submit_and_cancel() {
        let ladder = vec![100, 200, 300];
        let mut state = BatchState::new(10, ladder);

        let a = state.submit_order(0, 5, 100);
        let b = state.submit_order(1, 6, 200);
        let c = state.submit_order(2, 7, 300);

        assert_eq!(a, 0);
        assert_eq!(b, 1);
        assert_eq!(c, 2);
        assert!(state.cancel_order(b));
        assert_eq!(state.active_orders.len(), 2);
        assert_eq!(
            state
                .active_orders
                .iter()
                .map(|order| order.order_id)
                .collect::<Vec<_>>(),
            vec![a, c]
        );
    }

    #[test]
    fn test_epoch_advance() {
        let mut state = BatchState::new(10, vec![100, 200, 300]);
        assert_eq!(state.epoch, 1);

        state.advance_epoch();
        assert_eq!(state.epoch, 2);
    }

    #[test]
    fn test_to_one_hot_basic() {
        let fixture = test_fixture();
        let slot_idx = PRICE_LEVELS / 2;
        let qty = 100;
        let price = fixture.price_ladder[slot_idx];

        let pt = encode_demand_vector(qty, price, &fixture.price_ladder, &fixture.params);
        let ct = encrypt_demand(&pt, &fixture.joint_pk);
        let one_hot = to_one_hot(&ct, &fixture.eval_key, &fixture.params);
        let slots = threshold_decrypt_slots(
            &one_hot,
            &fixture.participating,
            &fixture.sk_poly_sums,
            &fixture.params,
        );

        for (idx, &raw) in slots.iter().take(PRICE_LEVELS).enumerate() {
            let decoded = decode_demand_slot(raw, fixture.params.plaintext());
            let expected = if idx == slot_idx { qty } else { 0 };
            assert_eq!(decoded, expected, "one-hot mismatch at slot {idx}");
        }
    }

    #[test]
    fn test_classification_masks() {
        let params = build_params();

        for &clearing_idx in &[0usize, PRICE_LEVELS / 2, PRICE_LEVELS - 1] {
            let (winner_mask, loser_mask, marginal_mask) =
                build_classification_masks(clearing_idx, &params);

            let winner_slots = decode_plaintext_slots(&winner_mask);
            let loser_slots = decode_plaintext_slots(&loser_mask);
            let marginal_slots = decode_plaintext_slots(&marginal_mask);

            for idx in 0..PRICE_LEVELS {
                assert_eq!(winner_slots[idx], u64::from(idx > clearing_idx));
                assert_eq!(loser_slots[idx], u64::from(idx < clearing_idx));
                assert_eq!(marginal_slots[idx], u64::from(idx == clearing_idx));
            }
            assert!(winner_slots[PRICE_LEVELS..].iter().all(|&slot| slot == 0));
            assert!(loser_slots[PRICE_LEVELS..].iter().all(|&slot| slot == 0));
            assert!(marginal_slots[PRICE_LEVELS..].iter().all(|&slot| slot == 0));
        }
    }

    #[test]
    fn test_histogram_to_demand_curve() {
        let histogram = vec![4, 1, 3, 2];
        let demand_curve = histogram_to_demand_curve(&histogram);
        assert_eq!(demand_curve, vec![10, 6, 5, 2]);
    }

    #[test]
    fn test_encrypt_one_hot_residual() {
        let fixture = test_fixture();
        let slot_idx = PRICE_LEVELS / 3;
        let qty = 77;

        let ct = encrypt_one_hot_residual(qty, slot_idx, &fixture.params, &fixture.joint_pk);
        let slots = threshold_decrypt_slots(
            &ct,
            &fixture.participating,
            &fixture.sk_poly_sums,
            &fixture.params,
        );

        for (idx, &raw) in slots.iter().take(PRICE_LEVELS).enumerate() {
            let decoded = decode_demand_slot(raw, fixture.params.plaintext());
            let expected = if idx == slot_idx { qty } else { 0 };
            assert_eq!(decoded, expected, "residual mismatch at slot {idx}");
        }
    }

    #[test]
    fn test_decrypt_one_hot_slot() {
        let fixture = test_fixture();
        let slot_idx = PRICE_LEVELS / 2;
        let qty = 55;
        let price = fixture.price_ladder[slot_idx];

        let pt = encode_demand_vector(qty, price, &fixture.price_ladder, &fixture.params);
        let ct = encrypt_demand(&pt, &fixture.joint_pk);
        let one_hot = to_one_hot(&ct, &fixture.eval_key, &fixture.params);
        let (_, _, marginal_mask) = build_classification_masks(slot_idx, &fixture.params);

        let recovered = decrypt_one_hot_slot(
            &one_hot,
            &marginal_mask,
            slot_idx,
            &fixture.participating,
            &fixture.sk_poly_sums,
            &fixture.params,
        );

        assert_eq!(recovered, qty);
    }

    #[test]
    fn test_allocate_fba_strict_winners() {
        let bids = vec![
            order(0, 3, 500, 1),
            order(1, 2, 450, 1),
            order(2, 4, 300, 1),
        ];

        let allocations = allocate_fba(&bids, 0, 400, 5, &[9, 5]);
        assert_eq!(allocations, vec![(0, 3), (1, 2), (2, 0)]);
    }

    #[test]
    fn test_allocate_fba_time_priority() {
        let bids = vec![order(0, 4, 300, 1), order(1, 4, 300, 2)];

        let allocations = allocate_fba(&bids, 1, 300, 5, &[8, 8, 0]);
        assert_eq!(allocations, vec![(0, 4), (1, 1)]);
    }

    #[test]
    fn test_allocate_fba_prorata_within_epoch() {
        let bids = vec![
            order(0, 5, 300, 1),
            order(1, 3, 300, 1),
            order(2, 2, 300, 1),
        ];

        let allocations = allocate_fba(&bids, 3, 300, 7, &[10, 10, 10, 10]);
        assert_eq!(allocations, vec![(0, 4), (1, 2), (2, 1)]);
    }

    #[test]
    fn test_residual_computation() {
        assert_eq!(compute_residual_qty(11, 4), 7);
    }

    #[test]
    fn test_carry_forward_scenario() {
        let ladder = vec![100, 200, 300];
        let mut state = BatchState::new(7, ladder);

        let first = state.submit_order(0, 5, 300);
        let second = state.submit_order(1, 5, 300);

        let round_one = allocate_fba(&state.active_orders, 2, 300, 7, &[10, 10, 10]);
        let first_alloc = round_one
            .iter()
            .find(|&&(order_id, _)| order_id == first)
            .map(|&(_, allocation)| allocation)
            .expect("first order allocation");
        let second_alloc = round_one
            .iter()
            .find(|&&(order_id, _)| order_id == second)
            .map(|&(_, allocation)| allocation)
            .expect("second order allocation");

        state.active_orders[0].qty = compute_residual_qty(state.active_orders[0].qty, first_alloc);
        state.active_orders[1].qty = compute_residual_qty(state.active_orders[1].qty, second_alloc);
        state.active_orders.retain(|order| order.qty > 0);

        state.advance_epoch();
        let third = state.submit_order(2, 4, 300);

        let round_two = allocate_fba(&state.active_orders, 2, 300, 4, &[7, 7, 7]);
        assert_eq!(round_two, vec![(first, 1), (second, 2), (third, 1)]);
    }
}
