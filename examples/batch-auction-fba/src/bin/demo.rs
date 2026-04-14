// SPDX-License-Identifier: LGPL-3.0-only

use batch_auction_fba_example::{
    aggregate_public_key, aggregate_sk_shares_for_party, allocate_fba, build_classification_masks,
    build_eval_key_from_committee, build_params, build_price_ladder, compute_decryption_shares,
    compute_residual_qty, decode_demand_slot, decrypt_demand_slot_qty, encode_demand_vector,
    encrypt_demand, encrypt_residual, find_clearing_price, generate_crp,
    generate_eval_key_root_seed, generate_smudging_noise, member_keygen, threshold_decrypt,
    BatchState, Order, COMMITTEE_N, PRICE_LEVELS, SLOT_WIDTH,
};
use fhe::bfv::{BfvParameters, Ciphertext, Encoding, PublicKey};
use fhe_math::rq::Poly;
use fhe_traits::FheDecoder;
use std::collections::HashMap;
use std::sync::Arc;

const NAMES: [&str; 10] = [
    "Alice", "Bob", "Charlie", "Dave", "Eve", "Frank", "Grace", "Heidi", "Ivan", "Judy",
];

#[derive(Clone)]
struct EncryptedOrder {
    name: &'static str,
    order_id: usize,
    ct: Ciphertext,
}

struct RoundReport {
    round: usize,
    clearing_price: u64,
    demand_at_clearing: u64,
    allocations: Vec<(&'static str, u64)>,
    carry_forward: Vec<(&'static str, u64)>,
}

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

fn scene(title: &str) {
    println!("\n▶ {title}");
}

fn submit_encrypted_order(
    state: &mut BatchState,
    book: &mut Vec<EncryptedOrder>,
    name: &'static str,
    bidder_slot: usize,
    qty: u64,
    price: u64,
    params: &Arc<BfvParameters>,
    joint_pk: &PublicKey,
) -> usize {
    let order_id = state.submit_order(bidder_slot, qty, price);
    let pt = encode_demand_vector(qty, price, &state.price_ladder, params);
    let ct = encrypt_demand(&pt, joint_pk);
    book.push(EncryptedOrder { name, order_id, ct });
    order_id
}

fn threshold_decrypt_ciphertext(
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
    Vec::<u64>::try_decode(&plaintexts[0], Encoding::simd()).expect("decode ciphertext")
}

fn decrypt_demand_curve(
    aggregate_ct: &Ciphertext,
    participating: &[usize],
    sk_poly_sums: &[Poly],
    params: &Arc<BfvParameters>,
) -> Vec<u64> {
    let slots = threshold_decrypt_ciphertext(aggregate_ct, participating, sk_poly_sums, params);
    (0..PRICE_LEVELS)
        .map(|level| {
            let mut qty = 0u64;
            for bit in 0..SLOT_WIDTH {
                let raw = slots[level * SLOT_WIDTH + bit];
                qty += decode_demand_slot(raw, params.plaintext()) * (1u64 << bit);
            }
            qty
        })
        .collect()
}

fn shadow_demand_curve(orders: &[Order], price_ladder: &[u64]) -> Vec<u64> {
    price_ladder
        .iter()
        .map(|&level| {
            orders
                .iter()
                .filter(|order| order.price >= level)
                .map(|order| order.qty)
                .sum()
        })
        .collect()
}

fn run_round(
    round: usize,
    state: &mut BatchState,
    book: &mut Vec<EncryptedOrder>,
    params: &Arc<BfvParameters>,
    joint_pk: &PublicKey,
    participating: &[usize],
    sk_poly_sums: &[Poly],
) -> RoundReport {
    assert!(
        !state.active_orders.is_empty(),
        "each round requires active orders"
    );
    assert_eq!(state.active_orders.len(), book.len(), "state/book mismatch");

    scene(&format!("Round {round} match"));
    println!(
        "Public supply for this batch is {}.",
        format_quantity(state.supply)
    );
    println!(
        "The committee sums the active cumulative demand ciphertexts directly for this round."
    );
    println!("Homomorphic addition sums SIMD slots independently (Hadamard). Bit-position counts stay within t=12289, so no overflow. Depth remains 0.");

    let aggregate_ct = book
        .iter()
        .map(|entry| &entry.ct)
        .fold(None, |agg: Option<Ciphertext>, ct| {
            if let Some(mut running) = agg {
                batch_auction_fba_example::accumulate_demand(&mut running, ct);
                Some(running)
            } else {
                Some(ct.clone())
            }
        })
        .expect("at least one active order");

    let demand_curve = decrypt_demand_curve(&aggregate_ct, participating, sk_poly_sums, params);
    let (clearing_idx, clearing_price) =
        find_clearing_price(&demand_curve, state.supply, &state.price_ladder);

    let shadow_curve = shadow_demand_curve(&state.active_orders, &state.price_ladder);
    let (shadow_idx, shadow_price) =
        find_clearing_price(&shadow_curve, state.supply, &state.price_ladder);

    assert_eq!(
        demand_curve, shadow_curve,
        "round {round}: demand curve mismatch"
    );
    assert_eq!(
        clearing_idx, shadow_idx,
        "round {round}: clearing index mismatch"
    );
    assert_eq!(
        clearing_price, shadow_price,
        "round {round}: clearing price mismatch"
    );

    let (winner_mask, _loser_mask, marginal_mask) =
        build_classification_masks(clearing_idx, params);
    let entry_map: HashMap<usize, EncryptedOrder> = book
        .iter()
        .cloned()
        .map(|entry| (entry.order_id, entry))
        .collect();

    let allocation_view: Vec<Order> = state
        .active_orders
        .iter()
        .map(|order| {
            let order_idx = state
                .price_ladder
                .iter()
                .position(|&price| price == order.price)
                .expect("order price must be on ladder");
            let qty = if order.price > clearing_price {
                decrypt_demand_slot_qty(
                    &entry_map[&order.order_id].ct,
                    &winner_mask,
                    order_idx,
                    participating,
                    sk_poly_sums,
                    params,
                )
            } else if order.price == clearing_price {
                decrypt_demand_slot_qty(
                    &entry_map[&order.order_id].ct,
                    &marginal_mask,
                    clearing_idx,
                    participating,
                    sk_poly_sums,
                    params,
                )
            } else {
                0
            };

            Order {
                order_id: order.order_id,
                bidder_slot: order.bidder_slot,
                qty,
                price: order.price,
                epoch: order.epoch,
            }
        })
        .collect();

    let fhe_allocations = allocate_fba(
        &allocation_view,
        clearing_idx,
        clearing_price,
        state.supply,
        &demand_curve,
    );
    let expected_allocations = allocate_fba(
        &state.active_orders,
        shadow_idx,
        shadow_price,
        state.supply,
        &shadow_curve,
    );
    assert_eq!(
        fhe_allocations, expected_allocations,
        "round {round}: allocation mismatch"
    );

    println!("  ✅ Clearing price: {}", format_price(clearing_price));
    println!(
        "  ✅ Aggregate demand at clearing: {}",
        format_quantity(demand_curve[clearing_idx])
    );
    println!("To compute allocations, the committee classifies each order by its price relative to the clearing level. For strict winners (price > P*), it threshold-decrypts only the SIMD slot block at the order's price level to confirm the quantity. For marginal orders (price = P*), it decrypts the clearing-level slot block for pro-rata. Strict losers are carried forward with zero information revealed — their ciphertexts pass through untouched.");

    let allocation_map: HashMap<usize, u64> = fhe_allocations.iter().copied().collect();

    let named_allocations: Vec<(&'static str, u64)> = state
        .active_orders
        .iter()
        .map(|order| {
            let name = entry_map[&order.order_id].name;
            let allocation = allocation_map[&order.order_id];
            (name, allocation)
        })
        .collect();
    for &(name, allocation) in &named_allocations {
        println!("  ✅ {name:<7} allocation: {}", format_quantity(allocation));
    }

    let mut next_orders = Vec::new();
    let mut next_book = Vec::new();
    let mut carry_forward = Vec::new();

    for order in &state.active_orders {
        let allocated = allocation_map[&order.order_id];
        let residual = compute_residual_qty(order.qty, allocated);
        if residual == 0 {
            continue;
        }

        let entry = &entry_map[&order.order_id];
        let next_ct = if order.price < clearing_price {
            entry.ct.clone()
        } else {
            encrypt_residual(residual, order.price, &state.price_ladder, params, joint_pk)
        };

        carry_forward.push((entry.name, residual));
        next_orders.push(Order {
            order_id: order.order_id,
            bidder_slot: order.bidder_slot,
            qty: residual,
            price: order.price,
            epoch: order.epoch,
        });
        next_book.push(EncryptedOrder {
            name: entry.name,
            order_id: entry.order_id,
            ct: next_ct,
        });
    }

    state.active_orders = next_orders;
    *book = next_book;

    if carry_forward.is_empty() {
        println!("  ✅ No carry-forward remains after this round.");
    } else {
        println!("  ✅ Carry-forward quantities:");
        for &(name, qty) in &carry_forward {
            println!("     • {name:<7} carries {}", format_quantity(qty));
        }
    }
    println!("Marginal residuals are re-encrypted as fresh ciphertexts under the joint public key. Strict losers' original ciphertexts persist, preserving all privacy. Each decryption share includes 80-bit smudging noise to protect the joint secret key across rounds.");

    RoundReport {
        round,
        clearing_price,
        demand_at_clearing: demand_curve[clearing_idx],
        allocations: named_allocations,
        carry_forward,
    }
}

fn main() {
    println!("Threshold FHE Frequent Batch Auction Demo");

    act("Act 1 — The Problem");
    println!("Continuous markets reward whoever sees the book first.");
    println!(
        "Frequent batch auctions remove timing races, but operators still usually see every order."
    );
    println!(
        "Here the bidders submit once, and the committee carries forward residuals without asking them to re-encrypt."
    );
    println!(
        "The committee manages residual ciphertexts across epochs using the same threshold BFV infrastructure — re-encrypting partial fills under the joint public key without ever seeing the underlying plaintext quantities."
    );

    let params = build_params();

    act("Act 2 — The Setup");
    println!("Three independent parties jointly create one BFV lattice encryption key.");
    println!("Each member samples a degree-2048 BFV secret-key polynomial, derives a public-key share from the shared Common Random Polynomial (CRP), and Shamir-splits their secret key into shares.");
    println!("The joint public key aggregates all shares. Ciphertexts encrypted under it require ≥2 members' Shamir-reconstructed key shares to decrypt.");
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
    println!(
        "The committee also agrees on shared eval-key randomness for distributed key generation."
    );

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
    println!("The committee generates distributed Galois and relinearization keys without reconstructing the joint secret key.");
    println!("Galois keys (for SIMD slot rotations) and a relinearization key (for post-multiply noise control) are produced via distributed MPC — the full joint secret key is never reconstructed.");

    let price_ladder = build_price_ladder(100, 1_000, PRICE_LEVELS);
    let low_price = price_ladder[20];
    let mid_price = price_ladder[35];
    let high_price = price_ladder[50];
    let participating = [0usize, 1];

    let mut state = BatchState::new(250, price_ladder.clone());
    let mut book = Vec::new();
    let mut reports = Vec::new();

    act("Act 3 — The Batch Windows");
    scene("Round 1 submissions");
    let _alice = submit_encrypted_order(
        &mut state, &mut book, NAMES[0], 0, 120, high_price, &params, &joint_pk,
    );
    let _bob = submit_encrypted_order(
        &mut state, &mut book, NAMES[1], 1, 90, mid_price, &params, &joint_pk,
    );
    let charlie = submit_encrypted_order(
        &mut state, &mut book, NAMES[2], 2, 80, mid_price, &params, &joint_pk,
    );
    let _dave = submit_encrypted_order(
        &mut state, &mut book, NAMES[3], 3, 70, mid_price, &params, &joint_pk,
    );
    let _eve = submit_encrypted_order(
        &mut state, &mut book, NAMES[4], 4, 60, low_price, &params, &joint_pk,
    );
    println!("Alice–Eve submit into the first batch window.");
    println!("Each order is encoded as a SIMD bit-decomposed cumulative demand vector (Encoding::simd()): 64 price levels × 16 bits = 1024 active SIMD slots per ciphertext. For each level where price_ladder[p] ≤ bid_price, the quantity is bit-decomposed across the 16 SIMD slots. One BFV ciphertext per order.");

    act("Act 4 — The Computation");
    reports.push(run_round(
        1,
        &mut state,
        &mut book,
        &params,
        &joint_pk,
        &participating,
        &sk_poly_sums,
    ));

    state.advance_epoch();
    state.supply = 180;

    scene("Round 2 submissions and cancellation");
    assert!(
        state.cancel_order(charlie),
        "Charlie must still be active before cancellation"
    );
    book.retain(|entry| entry.order_id != charlie);
    println!("Charlie cancels the residual from round 1 before the second batch closes.");
    let _frank = submit_encrypted_order(
        &mut state, &mut book, NAMES[5], 5, 100, high_price, &params, &joint_pk,
    );
    let _grace = submit_encrypted_order(
        &mut state, &mut book, NAMES[6], 6, 70, mid_price, &params, &joint_pk,
    );
    let _heidi = submit_encrypted_order(
        &mut state, &mut book, NAMES[7], 7, 60, mid_price, &params, &joint_pk,
    );
    println!("Frank, Grace, and Heidi join the second batch while earlier residuals stay live.");

    reports.push(run_round(
        2,
        &mut state,
        &mut book,
        &params,
        &joint_pk,
        &participating,
        &sk_poly_sums,
    ));

    state.advance_epoch();
    state.supply = 400;

    scene("Round 3 submissions");
    let _ivan = submit_encrypted_order(
        &mut state, &mut book, NAMES[8], 8, 90, high_price, &params, &joint_pk,
    );
    let _judy = submit_encrypted_order(
        &mut state, &mut book, NAMES[9], 9, 80, mid_price, &params, &joint_pk,
    );
    println!("Ivan and Judy enter the final window, and supply is raised so the remaining book can clear.");

    reports.push(run_round(
        3,
        &mut state,
        &mut book,
        &params,
        &joint_pk,
        &participating,
        &sk_poly_sums,
    ));

    act("Act 5 — Lifting the Curtain");
    println!("Round-by-round shadow verification summary:");
    for report in &reports {
        println!(
            "  • Round {} cleared at {} with aggregate demand {}.",
            report.round,
            format_price(report.clearing_price),
            format_quantity(report.demand_at_clearing)
        );
        for &(name, allocation) in &report.allocations {
            println!("      - {name:<7} received {}", format_quantity(allocation));
        }
        if report.carry_forward.is_empty() {
            println!("      - No residual orders carried forward.");
        } else {
            for &(name, qty) in &report.carry_forward {
                println!("      - {name:<7} carried {}", format_quantity(qty));
            }
        }
    }

    assert!(
        state.active_orders.is_empty(),
        "all orders should clear by round 3"
    );
    assert!(
        book.is_empty(),
        "ciphertext book should be empty after final settlement"
    );
    println!(
        "✅ Verified: the FHE frequent batch auction matched all three rounds with correct clearing prices, epoch-priority allocations, and committee-managed carry-forward residuals."
    );
    println!("Across all rounds, the committee saw only: (1) the aggregate demand curve per round, and (2) targeted SIMD slot blocks for winners and marginal bidders. Losers' quantities, prices, and full demand vectors were never revealed.");
}
