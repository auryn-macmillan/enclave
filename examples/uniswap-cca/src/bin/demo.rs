// SPDX-License-Identifier: LGPL-3.0-only

use fhe::bfv::{BfvParameters, Ciphertext, Encoding};
use fhe_math::rq::Poly;
use fhe_traits::FheDecoder;
use rand::rngs::OsRng;
use rand::Rng;
use std::sync::Arc;
use uniswap_cca_example::{
    accumulate_demand, aggregate_public_key, aggregate_sk_shares_for_party,
    build_eval_key_from_committee, build_extraction_mask, build_params, build_price_ladder,
    compute_allocations_from_witness, compute_decryption_shares, decode_level_quantity,
    encode_demand_vector, encrypt_demand, find_clearing_price, find_clearing_price_by_search,
    generate_crp, generate_eval_key_root_seed, generate_smudging_noise, mask_multiply,
    member_keygen, threshold_decrypt, ClearingDemandWitness, COMMITTEE_N, PRICE_LEVELS,
};

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

fn decrypt_slots(
    ciphertext: &Ciphertext,
    participating: &[usize],
    sk_poly_sums: &[Poly],
    params: &Arc<BfvParameters>,
) -> Vec<u64> {
    let party_shares: Vec<(usize, Vec<_>)> = participating
        .iter()
        .map(|&i| {
            let smudging = generate_smudging_noise(params, 1);
            let shares = compute_decryption_shares(
                std::slice::from_ref(ciphertext),
                &sk_poly_sums[i],
                &smudging,
                params,
            );
            (i + 1, shares)
        })
        .collect();

    let plaintexts = threshold_decrypt(&party_shares, std::slice::from_ref(ciphertext), params);
    Vec::<u64>::try_decode(&plaintexts[0], Encoding::simd()).expect("decode masked slots")
}

fn decrypt_level_from_ciphertext(
    ciphertext: &Ciphertext,
    level: usize,
    participating: &[usize],
    sk_poly_sums: &[Poly],
    params: &Arc<BfvParameters>,
) -> u64 {
    let masked = mask_multiply(&build_extraction_mask(&[level], params), ciphertext);
    let slots = decrypt_slots(&masked, participating, sk_poly_sums, params);
    decode_level_quantity(&slots, level, params.plaintext())
}

fn main() {
    println!("Threshold FHE Sealed-Bid CCA Demo");

    act("Act 1 — The CCA Problem");
    println!("In a public CCA, every visible bid exposes trader intent before settlement.");
    println!("That visibility creates room for front-running, sandwiching, and MEV extraction.");
    println!("This demo asks: can a batch clear at one price without revealing the bids first?");

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
    println!("  Each member sampled a degree-8192 BFV secret-key polynomial s_i(x), computed a");
    println!("  public-key share from s_i and the shared CRP, then Shamir-split s_i into shares");
    println!("  for the other members. The joint public key is the sum of all pk shares.");
    println!("  Ciphertexts encrypted under it require >= 2 members to Shamir-reconstruct the");
    println!("  joint secret key before any decryption is possible.");
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
    println!("  Galois keys (11 rotations) and a relinearization key are produced via distributed");
    println!("  MPC over each member's sk share — the full joint secret key is never assembled.");
    println!("  These eval keys enable slot rotations and other advanced ciphertext operations when needed");

    act("Act 3 — The Encrypted Bids");
    let mut rng = OsRng;
    let price_ladder = build_price_ladder(1, 1_000, PRICE_LEVELS);

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

    println!();
    println!(
        "  Each bid is SIMD bit-decomposed into a cumulative demand vector (Encoding::simd())."
    );
    println!(
        "  Here N=8192 and t=65537, so the 8192 NTT slots hold 512 price levels x 16 bits each."
    );
    println!("  For every level p where price_ladder[p] <= bid_price, the bidder's quantity is");
    println!(
        "  bit-decomposed across the 16 SIMD slots of that level (bit 0 = LSB, bit 15 = MSB)."
    );
    println!("  This 8192-slot plaintext vector is encrypted into a single BFV ciphertext under");
    println!(
        "  the joint public key. The committee receives only the ciphertext — never the plaintext."
    );
    println!();
    println!(
        "Public supply for this batch is {}.",
        format_quantity(supply)
    );
    println!("Orders are accumulated into one encrypted demand curve.");
    println!("  Homomorphic BFV addition sums the SIMD slots element-wise (Hadamard addition).");
    println!(
        "  Each slot holds a single bit-position count; with t=65537 >> #bidders, no overflow"
    );
    println!(
        "  or carry propagation occurs. Result: 1 aggregate ciphertext, multiplicative depth 0."
    );
    println!("All orders are now locked in encrypted form. No single committee member can decrypt them alone, and the intended protocol flow avoids direct per-order decryption.");

    act("Act 4 — The Computation");
    println!("The encrypted demand curve is probed selectively to reveal only a small aggregate witness.");
    println!("The clearing price and allocations are being determined without decrypting any raw order...");

    let aggregate_ct = aggregate_ct.expect("at least one bidder");
    let participating = [0usize, 1];
    println!("Two committee members now cooperate for threshold decryption: 1 and 2.");
    println!("  Each member applies their Shamir-reconstructed sk polynomial to the ciphertext,");
    println!("  then adds 80-bit smudging noise to statistically mask any key-dependent leakage.");
    println!("  The two partial decryptions are combined via Lagrange interpolation only for");
    println!("  selected price buckets, enough to locate the clearing index by binary search.");

    let mut aggregate_levels = vec![None; PRICE_LEVELS];
    let (clearing_idx, clearing_price) =
        find_clearing_price_by_search(&price_ladder, supply, |idx| {
            if let Some(value) = aggregate_levels[idx] {
                return value;
            }

            let value = decrypt_level_from_ciphertext(
                &aggregate_ct,
                idx,
                &participating,
                &sk_poly_sums,
                &params,
            );
            aggregate_levels[idx] = Some(value);
            value
        });
    let demand_at_clearing = aggregate_levels[clearing_idx].expect("clearing level must be probed");
    let demand_above_clearing = if clearing_idx + 1 < PRICE_LEVELS {
        aggregate_levels[clearing_idx + 1].unwrap_or_else(|| {
            let value = decrypt_level_from_ciphertext(
                &aggregate_ct,
                clearing_idx + 1,
                &participating,
                &sk_poly_sums,
                &params,
            );
            aggregate_levels[clearing_idx + 1] = Some(value);
            value
        })
    } else {
        0
    };
    let witness = ClearingDemandWitness::new(
        clearing_idx,
        demand_at_clearing,
        demand_above_clearing,
        supply,
    );

    println!();
    println!("  ✅ Clearing price: {}", format_price(clearing_price));
    println!(
        "  ✅ Aggregate demand at clearing: {}",
        format_quantity(witness.demand_at_clearing)
    );
    if witness.undersubscribed {
        println!("  ✅ Aggregate witness: batch is undersubscribed at the minimum price.");
    } else {
        println!(
            "  ✅ Aggregate demand strictly above clearing: {}",
            format_quantity(witness.demand_above_clearing)
        );
    }
    println!();
    println!("  The committee now decrypts bidder buckets only as needed for settlement.");
    println!("  Easy cases reveal only the clearing bucket k. General cases first reveal k+1 to");
    println!("  identify strict winners, then reveal k only for bidders still ambiguous.");
    println!();

    let mut bidder_slot_values = Vec::with_capacity(per_bidder_cts.len());
    let reveal_above_clearing = witness.needs_above_clearing_reveal(PRICE_LEVELS);
    let mut revealed_at_clearing = 0usize;
    let mut revealed_above_clearing = 0usize;

    for bidder_ct in &per_bidder_cts {
        let above_clearing = if reveal_above_clearing {
            revealed_above_clearing += 1;
            decrypt_level_from_ciphertext(
                bidder_ct,
                clearing_idx + 1,
                &participating,
                &sk_poly_sums,
                &params,
            )
        } else {
            0
        };
        let at_clearing = if witness.bidder_needs_at_clearing_reveal(
            PRICE_LEVELS,
            reveal_above_clearing.then_some(above_clearing),
        ) {
            revealed_at_clearing += 1;
            decrypt_level_from_ciphertext(
                bidder_ct,
                clearing_idx,
                &participating,
                &sk_poly_sums,
                &params,
            )
        } else {
            above_clearing
        };
        bidder_slot_values.push((at_clearing, above_clearing));
    }

    let allocations = compute_allocations_from_witness(&bidder_slot_values, supply, witness);

    for ((name, _, _), allocation) in bids.iter().zip(allocations.iter()) {
        println!(
            "  ✅ {name:<7} allocation: {}",
            format_quantity(*allocation)
        );
    }

    println!();
    println!("  ❌ No full per-bidder price ladder position was revealed");
    println!("  ❌ No full bidder demand vector was revealed");
    println!("  ❌ No committee member saw any plaintext order book");
    println!();
    println!("  What the committee did see: (1) a small aggregate witness, not the full curve;");
    println!(
        "  (2) {} bidder reveals at k and {} bidder reveals at k+1.",
        revealed_at_clearing, revealed_above_clearing
    );
    println!("  They never saw any bidder's full 512-level demand vector or any quantity at");
    println!("  non-clearing price levels outside those gated reveals.");

    act("Act 5 — Lifting the Curtain");
    println!("A plaintext shadow is checked internally, but not printed.");

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

    assert_eq!(
        witness.demand_at_clearing, expected_curve[clearing_idx],
        "aggregate witness D[k] mismatch"
    );
    assert_eq!(
        witness.demand_above_clearing,
        expected_curve.get(clearing_idx + 1).copied().unwrap_or(0),
        "aggregate witness D[k+1] mismatch"
    );
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
        "✅ Verified: the FHE sealed-bid CCA produced the correct clearing price and allocations — without ever seeing the orders."
    );
}
