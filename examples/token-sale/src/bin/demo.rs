// SPDX-License-Identifier: LGPL-3.0-only

use fhe::bfv::{Encoding, Plaintext};
use fhe_traits::{FheDecoder, FheEncoder};
use token_sale_example::{
    accumulate_demand, aggregate_public_key, aggregate_sk_shares_for_party,
    build_eval_key_from_committee, build_params, build_price_ladder, compute_allocations,
    compute_collateral, compute_decryption_shares, compute_payment, compute_refund,
    decode_demand_slot, encode_capped_demand_vector, encrypt_demand, find_clearing_price,
    generate_crp, generate_eval_key_root_seed, generate_smudging_noise, member_keygen,
    threshold_decrypt, SaleConfig, COMMITTEE_N, PRICE_LEVELS, SLOTS,
};

const NAMES: [&str; 10] = [
    "Alice", "Bob", "Charlie", "Dave", "Eve", "Frank", "Grace", "Heidi", "Ivan", "Judy",
];

#[derive(Clone, Copy, Debug)]
struct DemoBid {
    name: &'static str,
    requested_lots: u64,
    clamped_lots: u64,
    price: u64,
}

fn format_price(price: u64) -> String {
    format!("${price}")
}

fn format_lots(lots: u64) -> String {
    format!("{lots} lots")
}

fn format_tokens(lots: u64, lot_size: u64) -> String {
    format!("{} tokens", lots * lot_size)
}

fn act(title: &str) {
    println!("\n════════════════════════════════════════════════════════════");
    println!("{title}");
    println!("────────────────────────────────────────────────────────────");
}

fn clamp_lots(requested_lots: u64, config: &SaleConfig) -> u64 {
    requested_lots.min(config.cap_k)
}

fn shadow_demand_curve(bids: &[DemoBid], price_ladder: &[u64]) -> Vec<u64> {
    price_ladder
        .iter()
        .map(|&level| {
            bids.iter()
                .filter(|bid| bid.price >= level)
                .map(|bid| bid.clamped_lots)
                .sum()
        })
        .collect()
}

fn shadow_allocations(
    bids: &[DemoBid],
    clearing_idx: usize,
    clearing_price: u64,
    supply: u64,
    demand_curve: &[u64],
) -> Vec<u64> {
    if demand_curve[0] < supply {
        return bids.iter().map(|bid| bid.clamped_lots).collect();
    }

    let strict_demand = demand_curve.get(clearing_idx + 1).copied().unwrap_or(0);
    let remaining_supply = supply.saturating_sub(strict_demand);
    let total_marginal = demand_curve[clearing_idx].saturating_sub(strict_demand);

    let mut allocations = vec![0u64; bids.len()];
    let mut marginal: Vec<(usize, u64, u128)> = Vec::new();

    for (slot, bid) in bids.iter().enumerate() {
        if bid.price > clearing_price {
            allocations[slot] = bid.clamped_lots;
        } else if bid.price == clearing_price {
            let scaled = (bid.clamped_lots as u128) * (remaining_supply as u128);
            let floor = if total_marginal == 0 {
                0
            } else {
                (scaled / total_marginal as u128) as u64
            };
            let remainder = if total_marginal == 0 {
                0
            } else {
                scaled % total_marginal as u128
            };
            allocations[slot] = floor;
            marginal.push((slot, floor, remainder));
        }
    }

    let floor_sum: u64 = allocations.iter().sum();
    let leftover = supply.saturating_sub(floor_sum);
    marginal.sort_by(|a, b| b.2.cmp(&a.2).then(a.0.cmp(&b.0)));

    for (slot, _, _) in marginal.into_iter().take(leftover as usize) {
        allocations[slot] += 1;
    }

    allocations
}

fn main() {
    println!("Threshold FHE Capped Token Sale Demo");

    act("Act 1 — The Problem");
    println!("A fair launch should clear demand without exposing every individual order.");
    println!("It should also stop whales from dominating the sale with oversized bids.");
    println!("Here, bidders submit encrypted capped lot-demand vectors under one joint BFV key.");

    let params = build_params();
    let price_ladder = build_price_ladder(100, 1_000, PRICE_LEVELS);
    let config = SaleConfig {
        lot_size: 100,
        cap_k: 500,
        total_supply_lots: 1_600,
        price_ladder,
    };

    act("Act 2 — The Setup");
    println!("Three independent parties jointly create one BFV lattice encryption key.");
    println!("No single party can decrypt alone — at least 2 of 3 must cooperate.");
    println!(
        "This token sale reuses the same zero-depth cumulative-demand circuit as the uniform-price auction."
    );

    let crp = generate_crp(&params);
    let members: Vec<_> = (0..COMMITTEE_N)
        .map(|i| {
            let member = member_keygen(&params, &crp);
            println!("Committee member {} creates a key share.", i + 1);
            member
        })
        .collect();

    let pk_shares: Vec<_> = members.iter().map(|m| m.pk_share.clone()).collect();
    let joint_pk = aggregate_public_key(pk_shares);
    println!("The committee aggregates those shares into one joint public key.");
    let eval_key_root_seed = generate_eval_key_root_seed();
    println!(
        "The committee also agrees on shared eval-key randomness for distributed key generation."
    );

    let all_sk_shares: Vec<_> = members.iter().map(|m| m.sk_shares.clone()).collect();
    let sk_poly_sums: Vec<_> = (0..COMMITTEE_N)
        .map(|i| aggregate_sk_shares_for_party(&all_sk_shares, i, &params))
        .collect();

    let member_sk_refs: Vec<&_> = members.iter().map(|m| &m.sk).collect();
    let (_eval_key, _relin_key) =
        build_eval_key_from_committee(&member_sk_refs, &params, &eval_key_root_seed);
    println!("The committee generates distributed Galois and relinearization keys without reconstructing the joint secret key.");

    act("Act 3 — The Commitment Phase");
    println!("Public sale parameters:");
    println!("  • Lot size: {}", format_tokens(1, config.lot_size));
    println!("  • Per-bidder cap: {}", format_lots(config.cap_k));
    println!(
        "  • Total supply: {} ({})",
        format_lots(config.total_supply_lots),
        format_tokens(config.total_supply_lots, config.lot_size)
    );
    println!(
        "  • Price ladder: {} levels from {} to {}",
        config.price_ladder.len(),
        format_price(config.price_ladder[0]),
        format_price(*config.price_ladder.last().expect("price ladder"))
    );

    let bid_specs = [
        (650u64, 35usize),
        (450, 35),
        (320, 42),
        (280, 42),
        (150, 49),
        (500, 28),
        (260, 28),
        (180, 21),
        (90, 14),
        (210, 7),
    ];

    let bids: Vec<DemoBid> = NAMES
        .iter()
        .zip(bid_specs.iter())
        .map(|(&name, &(requested_lots, price_idx))| DemoBid {
            name,
            requested_lots,
            clamped_lots: clamp_lots(requested_lots, &config),
            price: config.price_ladder[price_idx],
        })
        .collect();

    let total_capped_demand: u64 = bids.iter().map(|bid| bid.clamped_lots).sum();
    assert!(
        total_capped_demand < 6_144,
        "aggregate demand must stay below t/2"
    );
    assert!(bids.len() <= SLOTS, "too many bidders for SIMD slots");

    let mut aggregate_ct = None;
    let mut per_bidder_cts = Vec::with_capacity(bids.len());
    let mut collaterals = Vec::with_capacity(bids.len());

    for bid in &bids {
        let demand_pt =
            encode_capped_demand_vector(bid.requested_lots, bid.price, &config, &params);
        let demand_ct = encrypt_demand(&demand_pt, &joint_pk);
        let collateral = compute_collateral(bid.price, bid.clamped_lots, config.lot_size);

        if let Some(global) = aggregate_ct.as_mut() {
            accumulate_demand(global, &demand_ct);
        } else {
            aggregate_ct = Some(demand_ct.clone());
        }

        per_bidder_cts.push(demand_ct);
        collaterals.push(collateral);
        println!(
            "{:<7} submits encrypted demand: requested {:>8}, clamped {:>8}, max price {:>6}, collateral locked {}",
            bid.name,
            format_lots(bid.requested_lots),
            format_lots(bid.clamped_lots),
            format_price(bid.price),
            format_price(collateral),
        );
    }

    println!("All bids are now fixed in encrypted form.");
    println!("Alice tried to request more than the cap, and the encoder clamped her bid before encryption.");

    act("Act 4 — The Settlement Phase");
    println!("The aggregator sums all encrypted capped demand vectors.");
    println!("Two committee members now threshold-decrypt only the market-wide demand curve and the two slots needed per bidder.");

    let aggregate_ct = aggregate_ct.expect("at least one bidder");
    let participating = [0usize, 1];
    let party_demand_shares: Vec<(usize, Vec<_>)> = participating
        .iter()
        .map(|&i| {
            let smudging = generate_smudging_noise(&params, 1);
            let shares = compute_decryption_shares(
                std::slice::from_ref(&aggregate_ct),
                &sk_poly_sums[i],
                &smudging,
                &params,
            );
            (i + 1, shares)
        })
        .collect();

    let demand_pts = threshold_decrypt(
        &party_demand_shares,
        std::slice::from_ref(&aggregate_ct),
        &params,
    );
    let demand_slots =
        Vec::<u64>::try_decode(&demand_pts[0], Encoding::simd()).expect("decode demand");
    let demand_curve: Vec<u64> = (0..PRICE_LEVELS)
        .map(|idx| decode_demand_slot(demand_slots[idx], params.plaintext()))
        .collect();
    let (clearing_idx, clearing_price) = find_clearing_price(
        &demand_curve,
        config.total_supply_lots,
        &config.price_ladder,
    );

    println!("  ✅ Clearing price: {}", format_price(clearing_price));
    println!(
        "  ✅ Aggregate capped demand at clearing: {}",
        format_lots(demand_curve[clearing_idx])
    );

    let mut mask_slots = vec![0u64; SLOTS];
    mask_slots[clearing_idx] = 1;
    if clearing_idx + 1 < PRICE_LEVELS {
        mask_slots[clearing_idx + 1] = 1;
    }
    let mask_pt =
        Plaintext::try_encode(&mask_slots, Encoding::simd(), &params).expect("encode mask");

    let mut bidder_slot_values = Vec::with_capacity(per_bidder_cts.len());
    for bidder_ct in &per_bidder_cts {
        let masked_ct = bidder_ct * &mask_pt;
        let party_bidder_shares: Vec<(usize, Vec<_>)> = participating
            .iter()
            .map(|&i| {
                let smudging = generate_smudging_noise(&params, 1);
                let shares = compute_decryption_shares(
                    std::slice::from_ref(&masked_ct),
                    &sk_poly_sums[i],
                    &smudging,
                    &params,
                );
                (i + 1, shares)
            })
            .collect();

        let bidder_pts = threshold_decrypt(
            &party_bidder_shares,
            std::slice::from_ref(&masked_ct),
            &params,
        );
        let bidder_slots =
            Vec::<u64>::try_decode(&bidder_pts[0], Encoding::simd()).expect("decode masked bidder");
        let at_clearing = decode_demand_slot(bidder_slots[clearing_idx], params.plaintext());
        let above_clearing = if clearing_idx + 1 < PRICE_LEVELS {
            decode_demand_slot(bidder_slots[clearing_idx + 1], params.plaintext())
        } else {
            0
        };
        bidder_slot_values.push((at_clearing, above_clearing));
    }

    let allocations = compute_allocations(
        &bidder_slot_values,
        clearing_idx,
        config.total_supply_lots,
        &demand_curve,
    );

    println!();
    for ((bid, &allocation), &collateral) in
        bids.iter().zip(allocations.iter()).zip(collaterals.iter())
    {
        let payment = compute_payment(clearing_price, allocation, config.lot_size);
        let refund = compute_refund(collateral, payment);
        println!(
            "{:<7} requested {:>8}, clamped {:>8}, allocation {:>8}, payment {:>10}, refund {:>10}",
            bid.name,
            format_lots(bid.requested_lots),
            format_lots(bid.clamped_lots),
            format_lots(allocation),
            format_price(payment),
            format_price(refund),
        );
    }

    println!();
    println!("  ❌ No raw unclamped quantity was decrypted");
    println!("  ❌ No bidder's full demand vector was revealed");
    println!("  ❌ No committee member saw a plaintext order book");

    act("Act 5 — Lifting the Curtain");
    println!("Let's verify the encrypted sale against the plaintext shadow computation:");

    for (rank, bid) in bids.iter().enumerate() {
        println!(
            "{:>2}. {:<7} requested {:>8}, clamped {:>8}, max price {}",
            rank + 1,
            bid.name,
            format_lots(bid.requested_lots),
            format_lots(bid.clamped_lots),
            format_price(bid.price),
        );
    }

    let expected_curve = shadow_demand_curve(&bids, &config.price_ladder);
    let (expected_clearing_idx, expected_clearing_price) = find_clearing_price(
        &expected_curve,
        config.total_supply_lots,
        &config.price_ladder,
    );
    let expected_allocations = shadow_allocations(
        &bids,
        expected_clearing_idx,
        expected_clearing_price,
        config.total_supply_lots,
        &expected_curve,
    );

    assert_eq!(demand_curve, expected_curve, "demand curve mismatch");
    assert_eq!(
        clearing_idx, expected_clearing_idx,
        "clearing index mismatch"
    );
    assert_eq!(
        clearing_price, expected_clearing_price,
        "clearing price mismatch"
    );
    assert_eq!(allocations, expected_allocations, "allocation mismatch");

    for (((bid, &allocation), &expected_allocation), &collateral) in bids
        .iter()
        .zip(allocations.iter())
        .zip(expected_allocations.iter())
        .zip(collaterals.iter())
    {
        let payment = compute_payment(clearing_price, allocation, config.lot_size);
        let expected_payment = compute_payment(
            expected_clearing_price,
            expected_allocation,
            config.lot_size,
        );
        let refund = compute_refund(collateral, payment);
        let expected_refund = compute_refund(collateral, expected_payment);

        assert_eq!(
            payment, expected_payment,
            "payment mismatch for {}",
            bid.name
        );
        assert_eq!(refund, expected_refund, "refund mismatch for {}", bid.name);
    }

    println!("✅ Verified: the FHE capped token sale produced the correct clearing price, allocations, payments, and refunds — without ever seeing the bids.");
}
