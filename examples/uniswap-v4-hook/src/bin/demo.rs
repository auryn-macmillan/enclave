// SPDX-License-Identifier: LGPL-3.0-only

use fhe::bfv::{BfvParameters, Ciphertext, Encoding, Plaintext};
use fhe_math::rq::Poly;
use fhe_traits::{FheDecoder, FheEncoder};
use std::sync::Arc;
use uniswap_v4_hook_example::{
    accumulate_demand, aggregate_public_key, aggregate_sk_shares_for_party,
    build_eval_key_from_committee, build_params, build_price_ladder, compute_decryption_shares,
    compute_net_flow, compute_two_sided_allocations, decode_demand_curve, decode_demand_slot,
    encode_buy_demand_vector, encode_sell_supply_vector, encrypt_demand,
    find_two_sided_clearing_price, generate_crp, generate_eval_key_root_seed,
    generate_smudging_noise, member_keygen, threshold_decrypt, COMMITTEE_N, PRICE_LEVELS,
    SLOT_WIDTH,
};

const BUYER_NAMES: [&str; 5] = ["Alice", "Bob", "Charlie", "Dave", "Eve"];
const SELLER_NAMES: [&str; 5] = ["Frank", "Grace", "Heidi", "Ivan", "Judy"];

struct EncryptedOrder {
    name: &'static str,
    qty: u64,
    price: u64,
    ct: Ciphertext,
}

fn act(title: &str) {
    println!("\n════════════════════════════════════════════════════════════");
    println!("{title}");
    println!("────────────────────────────────────────────────────────────");
}

fn format_price(price: u64) -> String {
    format!("${price}")
}

fn format_quantity(qty: u64) -> String {
    format!("{qty} units")
}

fn shadow_buy_curve(orders: &[EncryptedOrder], price_ladder: &[u64]) -> Vec<u64> {
    price_ladder
        .iter()
        .map(|&price| {
            orders
                .iter()
                .filter(|order| order.price >= price)
                .map(|order| order.qty)
                .sum()
        })
        .collect()
}

fn shadow_sell_curve(orders: &[EncryptedOrder], price_ladder: &[u64]) -> Vec<u64> {
    price_ladder
        .iter()
        .map(|&price| {
            orders
                .iter()
                .filter(|order| order.price <= price)
                .map(|order| order.qty)
                .sum()
        })
        .collect()
}

fn decrypt_curve(
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
    let pts = threshold_decrypt(&party_shares, std::slice::from_ref(ct), params);
    let slots = Vec::<u64>::try_decode(&pts[0], Encoding::simd()).expect("decode curve");

    decode_demand_curve(&slots, PRICE_LEVELS, params.plaintext())
}

fn decrypt_masked_slots(
    ct: &Ciphertext,
    mask_pt: &Plaintext,
    participating: &[usize],
    sk_poly_sums: &[Poly],
    params: &Arc<BfvParameters>,
) -> Vec<u64> {
    let masked = ct * mask_pt;

    let party_shares: Vec<(usize, Vec<_>)> = participating
        .iter()
        .map(|&i| {
            let smudging = generate_smudging_noise(params, 1);
            let shares = compute_decryption_shares(
                std::slice::from_ref(&masked),
                &sk_poly_sums[i],
                &smudging,
                params,
            );
            (i + 1, shares)
        })
        .collect();
    let pts = threshold_decrypt(&party_shares, std::slice::from_ref(&masked), params);

    Vec::<u64>::try_decode(&pts[0], Encoding::simd()).expect("decode masked slots")
}

fn main() {
    println!("Threshold FHE Encrypted Batch Settlement (v4 Hook) Demo");

    act("Act 1 — The MEV Problem");
    println!("Public swap intent on Uniswap v4 invites front-running and sandwich attacks.");
    println!("This demo batches encrypted buy and sell intents for one epoch, clears them offchain, and reveals only the settlement data needed to execute the batch.");
    println!("Instead of racing individual swaps through a visible mempool, traders submit one encrypted BFV ciphertext each and share a single clearing price.");

    let params = build_params();

    act("Act 2 — The Committee Setup");
    println!("Three independent parties jointly create one BFV key for an N=8192 ring with plaintext modulus t=65537.");
    println!("The committee uses the existing 2-of-3 DKG, Shamir threshold shares, and smudged threshold decryption pipeline.");
    println!("No single party can decrypt alone, and distributed evaluation keys are generated without reconstructing the joint secret key.");

    let crp = generate_crp(&params);
    let members: Vec<_> = (0..COMMITTEE_N)
        .map(|i| {
            let member = member_keygen(&params, &crp);
            println!("Committee member {} creates a key share.", i + 1);
            member
        })
        .collect();

    let pk_shares: Vec<_> = members
        .iter()
        .map(|member| member.pk_share.clone())
        .collect();
    let joint_pk = aggregate_public_key(pk_shares);
    println!("The committee aggregates those shares into one joint public key.");

    let eval_key_root_seed = generate_eval_key_root_seed();
    let all_sk_shares: Vec<_> = members
        .iter()
        .map(|member| member.sk_shares.clone())
        .collect();
    let sk_poly_sums: Vec<_> = (0..COMMITTEE_N)
        .map(|i| aggregate_sk_shares_for_party(&all_sk_shares, i, &params))
        .collect();
    let member_sk_refs: Vec<&_> = members.iter().map(|member| &member.sk).collect();
    let (_eval_key, _relin_key) =
        build_eval_key_from_committee(&member_sk_refs, &params, &eval_key_root_seed);
    println!("The committee also derives distributed evaluation keys for the shared BFV instance.");

    act("Act 3 — Epoch Submission");
    println!("This epoch uses a 512-level public price ladder under the N=8192, SLOT_WIDTH=16 SIMD layout.");
    println!("Five buyers and five sellers submit encrypted intents during the batch window. The hook accumulates ciphertexts offchain and settles once per epoch.");

    let price_ladder = build_price_ladder(100, 10_000, PRICE_LEVELS);
    let p64 = price_ladder[64];
    let p160 = price_ladder[160];
    let p256 = price_ladder[256];
    let p352 = price_ladder[352];
    let p448 = price_ladder[448];

    let buyers_plain = [
        (BUYER_NAMES[0], 220, p448),
        (BUYER_NAMES[1], 180, p352),
        (BUYER_NAMES[2], 150, p256),
        (BUYER_NAMES[3], 130, p160),
        (BUYER_NAMES[4], 90, p64),
    ];
    let sellers_plain = [
        (SELLER_NAMES[0], 160, p64),
        (SELLER_NAMES[1], 120, p160),
        (SELLER_NAMES[2], 110, p256),
        (SELLER_NAMES[3], 80, p256),
        (SELLER_NAMES[4], 60, p352),
    ];

    assert!(
        buyers_plain.len() < params.plaintext() as usize / 2,
        "too many buyers for plaintext modulus"
    );
    assert!(
        sellers_plain.len() < params.plaintext() as usize / 2,
        "too many sellers for plaintext modulus"
    );

    let mut aggregate_buy_ct: Option<Ciphertext> = None;
    let mut aggregate_sell_ct: Option<Ciphertext> = None;
    let mut buyer_orders = Vec::new();
    let mut seller_orders = Vec::new();

    for &(name, qty, max_price) in &buyers_plain {
        let pt = encode_buy_demand_vector(qty, max_price, &price_ladder, &params);
        let ct = encrypt_demand(&pt, &joint_pk);
        if let Some(running) = aggregate_buy_ct.as_mut() {
            accumulate_demand(running, &ct);
        } else {
            aggregate_buy_ct = Some(ct.clone());
        }
        buyer_orders.push(EncryptedOrder {
            name,
            qty,
            price: max_price,
            ct,
        });
        println!("{name:<7} submits an encrypted buy intent.");
    }
    println!("Each buy intent is a descending step function over 512 price levels, encoded as 16 SIMD slots per level.");

    for &(name, qty, min_price) in &sellers_plain {
        let pt = encode_sell_supply_vector(qty, min_price, &price_ladder, &params);
        let ct = encrypt_demand(&pt, &joint_pk);
        if let Some(running) = aggregate_sell_ct.as_mut() {
            accumulate_demand(running, &ct);
        } else {
            aggregate_sell_ct = Some(ct.clone());
        }
        seller_orders.push(EncryptedOrder {
            name,
            qty,
            price: min_price,
            ct,
        });
        println!("{name:<7} submits an encrypted sell intent.");
    }
    println!("Each sell intent is an ascending step function. The hook now holds one encrypted aggregate buy curve and one encrypted aggregate sell curve for the epoch.");

    act("Act 4 — Clearing and Hook Settlement");
    println!("Two committee members threshold-decrypt only the aggregate curves needed to find the clearing price on the 512-level ladder.");
    println!("They then decrypt only the masked slots needed to distinguish strict from marginal participants on the rationed side.");

    let aggregate_buy_ct = aggregate_buy_ct.expect("at least one buyer");
    let aggregate_sell_ct = aggregate_sell_ct.expect("at least one seller");
    let participating = [0usize, 1];

    let buy_demand = decrypt_curve(&aggregate_buy_ct, &participating, &sk_poly_sums, &params);
    let sell_supply = decrypt_curve(&aggregate_sell_ct, &participating, &sk_poly_sums, &params);
    let (clearing_idx, clearing_price) =
        find_two_sided_clearing_price(&buy_demand, &sell_supply, &price_ladder)
            .expect("expected non-empty market intersection");

    println!("  ✅ Clearing price: {}", format_price(clearing_price));
    println!(
        "  ✅ Aggregate buy demand at clearing: {}",
        format_quantity(buy_demand[clearing_idx])
    );
    println!(
        "  ✅ Aggregate sell supply at clearing: {}",
        format_quantity(sell_supply[clearing_idx])
    );

    let buyers_rationed = buy_demand[clearing_idx] > sell_supply[clearing_idx];
    let sellers_rationed = sell_supply[clearing_idx] > buy_demand[clearing_idx];

    if buyers_rationed {
        println!(
            "Buy demand exceeds sell supply at the clearing price, so buyers are rationed. Buyer masks reveal k and k+1; seller masks reveal only k."
        );
    } else if sellers_rationed {
        println!(
            "Sell supply exceeds buy demand at the clearing price, so sellers are rationed. Seller masks reveal k and k-1; buyer masks reveal only k."
        );
    } else {
        println!(
            "Demand and supply match exactly at the clearing price, so both sides reveal only the clearing block k."
        );
    }

    let mut buyer_mask_slots = vec![0u64; params.degree()];
    for bit in 0..SLOT_WIDTH {
        buyer_mask_slots[clearing_idx * SLOT_WIDTH + bit] = 1;
        if buyers_rationed && clearing_idx + 1 < PRICE_LEVELS {
            buyer_mask_slots[(clearing_idx + 1) * SLOT_WIDTH + bit] = 1;
        }
    }
    let buyer_mask_pt = Plaintext::try_encode(&buyer_mask_slots, Encoding::simd(), &params)
        .expect("encode buyer mask");

    let mut seller_mask_slots = vec![0u64; params.degree()];
    for bit in 0..SLOT_WIDTH {
        seller_mask_slots[clearing_idx * SLOT_WIDTH + bit] = 1;
        if sellers_rationed && clearing_idx > 0 {
            seller_mask_slots[(clearing_idx - 1) * SLOT_WIDTH + bit] = 1;
        }
    }
    let seller_mask_pt = Plaintext::try_encode(&seller_mask_slots, Encoding::simd(), &params)
        .expect("encode seller mask");

    let buyer_values: Vec<(u64, u64)> = buyer_orders
        .iter()
        .map(|order| {
            let slots = decrypt_masked_slots(
                &order.ct,
                &buyer_mask_pt,
                &participating,
                &sk_poly_sums,
                &params,
            );
            let at_clearing = (0..SLOT_WIDTH)
                .map(|bit| {
                    decode_demand_slot(slots[clearing_idx * SLOT_WIDTH + bit], params.plaintext())
                        * (1u64 << bit)
                })
                .sum::<u64>();
            let above_clearing = if buyers_rationed && clearing_idx + 1 < PRICE_LEVELS {
                (0..SLOT_WIDTH)
                    .map(|bit| {
                        decode_demand_slot(
                            slots[(clearing_idx + 1) * SLOT_WIDTH + bit],
                            params.plaintext(),
                        ) * (1u64 << bit)
                    })
                    .sum::<u64>()
            } else {
                0
            };
            (at_clearing, above_clearing)
        })
        .collect();

    let seller_values: Vec<(u64, u64)> = seller_orders
        .iter()
        .map(|order| {
            let slots = decrypt_masked_slots(
                &order.ct,
                &seller_mask_pt,
                &participating,
                &sk_poly_sums,
                &params,
            );
            let at_clearing = (0..SLOT_WIDTH)
                .map(|bit| {
                    decode_demand_slot(slots[clearing_idx * SLOT_WIDTH + bit], params.plaintext())
                        * (1u64 << bit)
                })
                .sum::<u64>();
            let below_clearing = if sellers_rationed && clearing_idx > 0 {
                (0..SLOT_WIDTH)
                    .map(|bit| {
                        decode_demand_slot(
                            slots[(clearing_idx - 1) * SLOT_WIDTH + bit],
                            params.plaintext(),
                        ) * (1u64 << bit)
                    })
                    .sum::<u64>()
            } else {
                0
            };
            (at_clearing, below_clearing)
        })
        .collect();

    let (buyer_allocations, seller_allocations) = compute_two_sided_allocations(
        &buyer_values,
        &seller_values,
        clearing_idx,
        &buy_demand,
        &sell_supply,
    );

    for (order, allocation) in buyer_orders.iter().zip(buyer_allocations.iter()) {
        println!(
            "  ✅ buyer {:<7} allocation: {}",
            order.name,
            format_quantity(*allocation)
        );
    }
    for (order, allocation) in seller_orders.iter().zip(seller_allocations.iter()) {
        println!(
            "  ✅ seller {:<7} allocation: {}",
            order.name,
            format_quantity(*allocation)
        );
    }

    let matched_volume: u64 = buyer_allocations.iter().sum();
    let net_flow = compute_net_flow(&buyer_allocations, &seller_allocations);
    println!(
        "  ✅ Matched batch volume: {}",
        format_quantity(matched_volume)
    );
    println!("  ✅ Net flow from cleared batch: {net_flow} units");
    println!("In this demo the cleared buyer and seller allocations match exactly, so net flow is zero. In a real v4 hook, any residual imbalance after batch crossing would be settled once against the AMM pool.");

    act("Act 5 — Shadow Verification");
    let expected_buy_curve = shadow_buy_curve(&buyer_orders, &price_ladder);
    let expected_sell_curve = shadow_sell_curve(&seller_orders, &price_ladder);
    let (expected_clearing_idx, expected_clearing_price) =
        find_two_sided_clearing_price(&expected_buy_curve, &expected_sell_curve, &price_ladder)
            .expect("shadow market should clear");
    let expected_buyers_rationed =
        expected_buy_curve[expected_clearing_idx] > expected_sell_curve[expected_clearing_idx];
    let expected_sellers_rationed =
        expected_sell_curve[expected_clearing_idx] > expected_buy_curve[expected_clearing_idx];
    let expected_buyer_values: Vec<(u64, u64)> = buyer_orders
        .iter()
        .map(|order| {
            let at_clearing = if order.price >= expected_clearing_price {
                order.qty
            } else {
                0
            };
            let above_clearing = if expected_buyers_rationed
                && expected_clearing_idx + 1 < PRICE_LEVELS
                && order.price >= price_ladder[expected_clearing_idx + 1]
            {
                order.qty
            } else {
                0
            };
            (at_clearing, above_clearing)
        })
        .collect();
    let expected_seller_values: Vec<(u64, u64)> = seller_orders
        .iter()
        .map(|order| {
            let at_clearing = if order.price <= expected_clearing_price {
                order.qty
            } else {
                0
            };
            let below_clearing = if expected_sellers_rationed
                && expected_clearing_idx > 0
                && order.price <= price_ladder[expected_clearing_idx - 1]
            {
                order.qty
            } else {
                0
            };
            (at_clearing, below_clearing)
        })
        .collect();
    let (expected_buyer_allocations, expected_seller_allocations) = compute_two_sided_allocations(
        &expected_buyer_values,
        &expected_seller_values,
        expected_clearing_idx,
        &expected_buy_curve,
        &expected_sell_curve,
    );
    let expected_net_flow =
        compute_net_flow(&expected_buyer_allocations, &expected_seller_allocations);

    assert_eq!(buy_demand, expected_buy_curve, "buy curve mismatch");
    assert_eq!(sell_supply, expected_sell_curve, "sell curve mismatch");
    assert_eq!(
        clearing_idx, expected_clearing_idx,
        "clearing index mismatch"
    );
    assert_eq!(
        clearing_price, expected_clearing_price,
        "clearing price mismatch"
    );
    assert_eq!(buyer_values, expected_buyer_values, "buyer value mismatch");
    assert_eq!(
        seller_values, expected_seller_values,
        "seller value mismatch"
    );
    assert_eq!(
        buyer_allocations, expected_buyer_allocations,
        "buyer allocation mismatch"
    );
    assert_eq!(
        seller_allocations, expected_seller_allocations,
        "seller allocation mismatch"
    );
    assert_eq!(net_flow, expected_net_flow, "net flow mismatch");

    println!("Buyers:");
    for order in &buyer_orders {
        println!(
            "  • {:<7} bid {} @ max {}",
            order.name,
            format_quantity(order.qty),
            format_price(order.price)
        );
    }
    println!("Sellers:");
    for order in &seller_orders {
        println!(
            "  • {:<7} offered {} @ min {}",
            order.name,
            format_quantity(order.qty),
            format_price(order.price)
        );
    }
    println!("✅ Verified: the encrypted v4 hook batch produced the correct curves, clearing price, per-user fills, and settlement summary.");
}
