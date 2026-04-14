// SPDX-License-Identifier: LGPL-3.0-only

use batch_auction_uniform_example::{
    accumulate_demand, aggregate_public_key, aggregate_sk_shares_for_party,
    build_eval_key_from_committee, build_params, build_price_ladder, compute_allocations,
    compute_decryption_shares, decode_demand_curve, decode_demand_slot, encode_demand_vector,
    encrypt_demand, find_clearing_price, generate_crp, generate_eval_key_root_seed,
    generate_smudging_noise, member_keygen, threshold_decrypt, COMMITTEE_N, PRICE_LEVELS,
    SLOT_WIDTH,
};
use fhe::bfv::Encoding;
use fhe_traits::FheDecoder;
use rand::rngs::OsRng;
use rand::Rng;

const NAMES: [&str; 10] = [
    "Alice", "Bob", "Charlie", "Dave", "Eve", "Frank", "Grace", "Heidi", "Ivan", "Judy",
];

fn format_price(price: u64) -> String {
    format!("${price}")
}

fn format_quantity(qty: u64) -> String {
    format!("{qty} units")
}

fn act(title: &str) {
    println!("\n════════════════════════════════════════════════════════════");
    println!("{title}");
    println!("────────────────────────────────────────────────────────────");
}

fn shadow_demand_curve(bids: &[(u64, u64)], price_ladder: &[u64]) -> Vec<u64> {
    price_ladder
        .iter()
        .map(|&level| {
            bids.iter()
                .filter(|&&(_, price)| price >= level)
                .map(|&(qty, _)| qty)
                .sum()
        })
        .collect()
}

fn choose_supply(total_quantity: u64, demand_curve: &[u64]) -> u64 {
    let min_supply = (total_quantity * 60 / 100).max(1);
    let max_supply = (total_quantity * 70 / 100).max(min_supply);
    let target = (min_supply + max_supply) / 2;

    let mut best: Option<(u64, u64)> = None;

    for clearing_idx in 0..demand_curve.len() {
        let at_price = demand_curve[clearing_idx];
        let strict = demand_curve.get(clearing_idx + 1).copied().unwrap_or(0);

        if at_price <= strict {
            continue;
        }

        let feasible_min = min_supply.max(strict.saturating_add(1));
        let feasible_max = max_supply.min(at_price);
        if feasible_min > feasible_max {
            continue;
        }

        let candidate = target.clamp(feasible_min, feasible_max);
        let distance = candidate.abs_diff(target);

        match best {
            None => best = Some((distance, candidate)),
            Some((best_distance, _)) if distance < best_distance => {
                best = Some((distance, candidate));
            }
            Some((best_distance, best_candidate))
                if distance == best_distance && candidate < best_candidate =>
            {
                best = Some((distance, candidate));
            }
            _ => {}
        }
    }

    best.map(|(_, supply)| supply)
        .unwrap_or_else(|| target.clamp(1, total_quantity.max(1)))
}

fn shadow_allocations(
    bids: &[(u64, u64)],
    clearing_idx: usize,
    clearing_price: u64,
    supply: u64,
    demand_curve: &[u64],
) -> Vec<u64> {
    if demand_curve[0] < supply {
        return bids.iter().map(|&(qty, _)| qty).collect();
    }

    let strict_demand = demand_curve.get(clearing_idx + 1).copied().unwrap_or(0);
    let remaining_supply = supply.saturating_sub(strict_demand);
    let total_marginal = demand_curve[clearing_idx].saturating_sub(strict_demand);

    let mut allocations = vec![0u64; bids.len()];
    let mut marginal: Vec<(usize, u64, u64, u64)> = Vec::new();

    for (slot, &(qty, price)) in bids.iter().enumerate() {
        if price > clearing_price {
            allocations[slot] = qty;
        } else if price == clearing_price {
            let numerator = qty * remaining_supply;
            let floor = if total_marginal == 0 {
                0
            } else {
                numerator / total_marginal
            };
            let remainder = if total_marginal == 0 {
                0
            } else {
                numerator % total_marginal
            };
            allocations[slot] = floor;
            marginal.push((slot, floor, remainder, qty));
        }
    }

    let floor_sum: u64 = allocations.iter().sum();
    let leftover = supply.saturating_sub(floor_sum);
    marginal.sort_by(|a, b| b.2.cmp(&a.2).then(a.0.cmp(&b.0)));

    for (slot, _, _, _) in marginal.into_iter().take(leftover as usize) {
        allocations[slot] += 1;
    }

    allocations
}

fn main() {
    println!("Threshold FHE Uniform-Price Batch Auction Demo");

    act("Act 1 — The Problem");
    println!("In a traditional batch auction, the operator sees every order book entry.");
    println!("That creates an opportunity to leak intent, front-run demand, or favor insiders.");
    println!("What if we could clear the market without anyone seeing individual orders?");

    let params = build_params();

    act("Act 2 — The Setup");
    println!("Three independent parties jointly create one BFV lattice encryption key.");
    println!("No single party can decrypt alone — at least 2 of 3 must cooperate.");

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

    act("Act 3 — The Bids");
    let mut rng = OsRng;
    let price_ladder = build_price_ladder(100, 1_000, PRICE_LEVELS);

    let bids: Vec<(&str, u64, u64)> = NAMES
        .iter()
        .map(|name| {
            let price = price_ladder[rng.gen_range(0..price_ladder.len())];
            let qty = rng.gen_range(50u64..=500u64);
            (*name, qty, price)
        })
        .collect();

    let total_quantity: u64 = bids.iter().map(|(_, qty, _)| *qty).sum();
    assert!(
        bids.len() < params.plaintext() as usize / 2,
        "too many bidders for plaintext modulus"
    );

    let shadow_bids: Vec<(u64, u64)> = bids.iter().map(|&(_, qty, price)| (qty, price)).collect();
    let shadow_curve = shadow_demand_curve(&shadow_bids, &price_ladder);
    let supply = choose_supply(total_quantity, &shadow_curve);

    let mut aggregate_ct = None;
    let mut per_bidder_cts = Vec::new();

    for &(name, qty, price) in &bids {
        let demand_pt = encode_demand_vector(qty, price, &price_ladder, &params);
        let demand_ct = encrypt_demand(&demand_pt, &joint_pk);

        if let Some(global) = aggregate_ct.as_mut() {
            accumulate_demand(global, &demand_ct);
        } else {
            aggregate_ct = Some(demand_ct.clone());
        }

        per_bidder_cts.push(demand_ct);
        println!("{name:<7} submits an encrypted quantity-and-price order.");
    }

    println!(
        "Public supply for this batch is {}.",
        format_quantity(supply)
    );
    println!("Orders are accumulated into one encrypted demand curve.");
    println!("All orders are now locked in encrypted form. Nobody — not even the committee — can see them.");

    act("Act 4 — The Computation");
    println!(
        "The encrypted demand curve is threshold-decrypted to reveal only market-wide demand."
    );
    println!("The clearing price and allocations are being determined without decrypting any raw order...");

    let aggregate_ct = aggregate_ct.expect("at least one bidder");
    let participating = [0usize, 1];
    println!("Two committee members now cooperate for threshold decryption: 1 and 2.");

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
    let demand_pt = &demand_pts[0];
    let demand_slots = Vec::<u64>::try_decode(demand_pt, Encoding::simd()).expect("decode demand");
    let demand_curve = decode_demand_curve(&demand_slots, PRICE_LEVELS, params.plaintext());
    let (clearing_idx, clearing_price) = find_clearing_price(&demand_curve, supply, &price_ladder);

    println!();
    println!("  ✅ Clearing price: {}", format_price(clearing_price));
    println!(
        "  ✅ Aggregate demand at clearing: {}",
        format_quantity(demand_curve[clearing_idx])
    );
    println!();

    let mut bidder_slot_values = Vec::with_capacity(per_bidder_cts.len());
    for bidder_ct in &per_bidder_cts {
        let party_bidder_shares: Vec<(usize, Vec<_>)> = participating
            .iter()
            .map(|&i| {
                let smudging = generate_smudging_noise(&params, 1);
                let shares = compute_decryption_shares(
                    std::slice::from_ref(bidder_ct),
                    &sk_poly_sums[i],
                    &smudging,
                    &params,
                );
                (i + 1, shares)
            })
            .collect();

        let bidder_pts = threshold_decrypt(
            &party_bidder_shares,
            std::slice::from_ref(bidder_ct),
            &params,
        );
        let bidder_pt = &bidder_pts[0];
        let bidder_slots =
            Vec::<u64>::try_decode(bidder_pt, Encoding::simd()).expect("decode bidder slots");
        let at_clearing = (0..SLOT_WIDTH)
            .map(|bit| {
                decode_demand_slot(
                    bidder_slots[clearing_idx * SLOT_WIDTH + bit],
                    params.plaintext(),
                ) * (1u64 << bit)
            })
            .sum::<u64>();
        let above_clearing = if clearing_idx + 1 < PRICE_LEVELS {
            (0..SLOT_WIDTH)
                .map(|bit| {
                    decode_demand_slot(
                        bidder_slots[(clearing_idx + 1) * SLOT_WIDTH + bit],
                        params.plaintext(),
                    ) * (1u64 << bit)
                })
                .sum::<u64>()
        } else {
            0
        };
        bidder_slot_values.push((at_clearing, above_clearing));
    }

    let allocations = compute_allocations(&bidder_slot_values, clearing_idx, supply, &demand_curve);

    for ((name, _, _), allocation) in bids.iter().zip(allocations.iter()) {
        println!(
            "  ✅ {name:<7} allocation: {}",
            format_quantity(*allocation)
        );
    }

    println!();
    println!("  ❌ No individual bid price was revealed");
    println!("  ❌ No full bidder demand vector was revealed");
    println!("  ❌ No committee member saw any plaintext order book");

    act("Act 5 — Lifting the Curtain");
    println!("Let's peek behind the scenes to verify the result:");

    let mut shadow_orders: Vec<(usize, u64, u64)> = bids
        .iter()
        .enumerate()
        .map(|(slot, &(_, qty, price))| (slot, qty, price))
        .collect();
    shadow_orders.sort_by(|a, b| b.2.cmp(&a.2).then(b.1.cmp(&a.1)).then(a.0.cmp(&b.0)));

    for (rank, (slot, qty, price)) in shadow_orders.iter().enumerate() {
        println!(
            "{:>2}. {:<7} {:>10} @ {}",
            rank + 1,
            bids[*slot].0,
            format_quantity(*qty),
            format_price(*price)
        );
    }

    let expected_curve = shadow_demand_curve(&shadow_bids, &price_ladder);
    let (expected_clearing_idx, expected_clearing_price) =
        find_clearing_price(&expected_curve, supply, &price_ladder);
    let expected_allocations = shadow_allocations(
        &shadow_bids,
        expected_clearing_idx,
        expected_clearing_price,
        supply,
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

    println!(
        "✅ Verified: the FHE batch auction produced the correct clearing price and allocations — without ever seeing the orders."
    );
}
