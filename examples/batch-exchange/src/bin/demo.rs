// SPDX-License-Identifier: LGPL-3.0-only

use batch_exchange_example::{
    accumulate_demand, aggregate_public_key, aggregate_sk_shares_for_party,
    build_eval_key_from_committee, build_params, build_price_ladder, compute_decryption_shares,
    compute_two_sided_allocations, decode_demand_curve, decode_demand_slot,
    encode_buy_demand_vector, encode_sell_supply_vector, encrypt_demand,
    find_two_sided_clearing_price, generate_crp, generate_eval_key_root_seed,
    generate_smudging_noise, member_keygen, threshold_decrypt, COMMITTEE_N, PRICE_LEVELS,
    SLOT_WIDTH,
};
use fhe::bfv::{BfvParameters, Ciphertext, Encoding, Plaintext};
use fhe_math::rq::Poly;
use fhe_traits::{FheDecoder, FheEncoder};
use std::sync::Arc;

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
    println!("Threshold FHE Two-Sided Batch Exchange Demo");

    act("Act 1 — The Problem");
    println!("In a two-sided market, both buyers and sellers reveal sensitive intent.");
    println!("That exposes reservation prices, inventory pressure, and trading strategy.");
    println!("This demo clears one batch exchange while keeping individual orders encrypted.");
    println!("Buyers and sellers each encrypt a single BFV ciphertext encoding their quantity at every relevant price level. In the intended demo flow, the committee sees aggregate curves and the specific slot values needed for rationing rather than a full plaintext order book.");

    let params = build_params();

    act("Act 2 — The Setup");
    println!("Three independent parties jointly create one BFV lattice encryption key.");
    println!("Each member samples a degree-2048 BFV secret-key polynomial, computes a public-key share from a shared CRP, and Shamir-splits their secret key.");
    println!("The joint public key is the sum of all shares. Threshold decryption requires ≥2 members to contribute Shamir-reconstructed key shares, each protected by 80-bit smudging noise.");
    println!("No single party can decrypt alone — at least 2 of 3 must cooperate.");

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
    println!("The committee generates distributed evaluation keys without reconstructing the joint secret key.");
    println!("Galois keys and a relinearization key are generated via distributed MPC. The full joint secret key is never reconstructed.");

    act("Act 3 — The Submission Phase");
    let price_ladder = build_price_ladder(100, 1_000, PRICE_LEVELS);
    let p15 = price_ladder[15];
    let p25 = price_ladder[25];
    let p35 = price_ladder[35];
    let p45 = price_ladder[45];

    let buyers_plain = [
        (BUYER_NAMES[0], 220, p45),
        (BUYER_NAMES[1], 180, p35),
        (BUYER_NAMES[2], 150, p35),
        (BUYER_NAMES[3], 130, p25),
        (BUYER_NAMES[4], 90, p15),
    ];
    let sellers_plain = [
        (SELLER_NAMES[0], 160, p15),
        (SELLER_NAMES[1], 120, p25),
        (SELLER_NAMES[2], 110, p35),
        (SELLER_NAMES[3], 80, p35),
        (SELLER_NAMES[4], 60, p45),
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
        println!("{name:<7} submits an encrypted buy order.");
    }
    println!("Each buy order is encoded as a SIMD bit-decomposed descending step function (Encoding::simd()): for each price level ≤ max_price, the buyer's quantity is bit-decomposed across 16 SIMD slots. One ciphertext per buyer.");

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
        println!("{name:<7} submits an encrypted sell order.");
    }
    println!("Each sell order is an ascending step function: for each price level ≥ min_price, the seller's quantity is bit-decomposed across 16 SIMD slots. One ciphertext per seller.");

    println!("The aggregator now holds one encrypted cumulative buy curve and one encrypted cumulative sell curve.");
    println!("Accumulation is pure Hadamard addition (depth 0). The aggregate buy ciphertext encodes total demand at each of 64 price levels; the aggregate sell ciphertext encodes total supply. No rotations or multiplications needed.");

    act("Act 4 — The Settlement Phase");
    println!("Two committee members decrypt only the aggregate curves needed to clear the batch.");
    println!("Each member computes decryption shares with 80-bit smudging noise. Lagrange interpolation over 2 shares reconstructs both curve plaintexts. The committee now sees aggregate demand and supply at all 64 levels — but not any individual order.");

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
    println!("To determine per-participant allocations, the committee extracts targeted SIMD slot blocks from each participant's ciphertext. Buyers need blocks at the clearing price (k) and one level above (k+1) to distinguish marginal from strict winners. Sellers need blocks at k and one level below (k-1).");
    println!("The committee now applies a plaintext SIMD mask with 1s at the target positions using ct×pt slot-wise multiplication and threshold-decrypts only the masked result.");

    let mut buyer_mask_slots = vec![0u64; params.degree()];
    for bit in 0..SLOT_WIDTH {
        buyer_mask_slots[clearing_idx * SLOT_WIDTH + bit] = 1;
        if clearing_idx + 1 < PRICE_LEVELS {
            buyer_mask_slots[(clearing_idx + 1) * SLOT_WIDTH + bit] = 1;
        }
    }
    let buyer_mask_pt = Plaintext::try_encode(&buyer_mask_slots, Encoding::simd(), &params)
        .expect("encode buyer mask");

    let mut seller_mask_slots = vec![0u64; params.degree()];
    for bit in 0..SLOT_WIDTH {
        seller_mask_slots[clearing_idx * SLOT_WIDTH + bit] = 1;
        if clearing_idx > 0 {
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
            let above_clearing = if clearing_idx + 1 < PRICE_LEVELS {
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
            let below_clearing = if clearing_idx > 0 {
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
    println!("The committee saw: (1) aggregate buy and sell curves, (2) masked decryptions revealing each buyer's quantity at levels k and k+1, and (3) masked decryptions revealing each seller's quantity at levels k and k-1. In the intended demo flow, they did not directly decrypt full demand/supply vectors or quantities at non-adjacent levels. Marginal participants are, however, known to sit at the public clearing price.");

    act("Act 5 — Shadow Verification");
    let expected_buy_curve = shadow_buy_curve(&buyer_orders, &price_ladder);
    let expected_sell_curve = shadow_sell_curve(&seller_orders, &price_ladder);
    let (expected_clearing_idx, expected_clearing_price) =
        find_two_sided_clearing_price(&expected_buy_curve, &expected_sell_curve, &price_ladder)
            .expect("shadow market should clear");
    let expected_buyer_values: Vec<(u64, u64)> = buyer_orders
        .iter()
        .map(|order| {
            let at_clearing = if order.price >= expected_clearing_price {
                order.qty
            } else {
                0
            };
            let above_clearing = if expected_clearing_idx + 1 < PRICE_LEVELS
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
            let below_clearing = if expected_clearing_idx > 0
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
    assert_eq!(
        buyer_allocations, expected_buyer_allocations,
        "buyer allocation mismatch"
    );
    assert_eq!(
        seller_allocations, expected_seller_allocations,
        "seller allocation mismatch"
    );

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
    println!("✅ Verified: the FHE batch exchange produced the correct curves, clearing price, and per-participant allocations.");
}
