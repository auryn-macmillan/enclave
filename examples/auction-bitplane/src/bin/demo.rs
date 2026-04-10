// SPDX-License-Identifier: LGPL-3.0-only
//
//! Five-act threshold FHE Vickrey auction demo.

use auction_bitplane_example::{
    accumulate_bitplanes, aggregate_public_key, aggregate_sk_shares_for_party,
    build_eval_key_from_committee, build_params, compute_decryption_shares, compute_tallies,
    decode_bid, decode_tally_matrix, encode_bid_into_planes, encrypt_bitplanes, generate_crp,
    generate_smudging_noise, member_keygen, rank_bidders, threshold_decrypt, BID_BITS, COMMITTEE_N,
    SLOTS,
};
use fhe::bfv::Ciphertext;
use rand::rngs::OsRng;
use rand::Rng;

const NAMES: [&str; 10] = [
    "Alice", "Bob", "Charlie", "Dave", "Eve", "Frank", "Grace", "Heidi", "Ivan", "Judy",
];

fn format_eth(wei: u64) -> String {
    let whole = wei / 1_000_000_000_000_000_000;
    let frac = wei % 1_000_000_000_000_000_000;
    // Show 4 decimal places for readability (truncate, don't round).
    let frac4 = frac / 100_000_000_000_000;
    format!("{whole}.{frac4:04} ETH")
}

fn act(title: &str) {
    println!("\n════════════════════════════════════════════════════════════");
    println!("{title}");
    println!("────────────────────────────────────────────────────────────");
}

fn main() {
    println!("Threshold FHE Sealed-Bid Vickrey Auction Demo");

    act("Act 1 — The Problem");
    println!("In a traditional sealed-bid auction, the auctioneer sees every bid.");
    println!("That creates an opportunity to cheat, leak information, or front-run.");
    println!("What if we could determine the winner without anyone seeing the bids?");

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

    let all_sk_shares: Vec<_> = members.iter().map(|m| m.sk_shares.clone()).collect();
    let sk_poly_sums: Vec<_> = (0..COMMITTEE_N)
        .map(|i| aggregate_sk_shares_for_party(&all_sk_shares, i, &params))
        .collect();

    let member_sk_refs: Vec<&_> = members.iter().map(|m| &m.sk).collect();
    let (eval_key, relin_key) = build_eval_key_from_committee(&member_sk_refs, &params);
    println!("An evaluation key is built with a demo shortcut so the encrypted tally can run.");

    act("Act 3 — The Bids");
    let mut rng = OsRng;
    let bids: Vec<(&str, u64)> = NAMES
        .iter()
        .map(|name| {
            (
                *name,
                rng.gen_range(1_000_000_000_000_000_000u64..=15_000_000_000_000_000_000u64),
            )
        })
        .collect();
    assert!(bids.len() <= SLOTS, "too many bidders for SIMD slots");

    let mut global_bitplanes: Vec<Ciphertext> = Vec::new();
    let mut per_bidder_cts: Vec<Vec<Ciphertext>> = Vec::new();

    for (slot, &(name, wei)) in bids.iter().enumerate() {
        let planes = encode_bid_into_planes(wei, slot, &params);
        let encrypted = encrypt_bitplanes(&planes, &joint_pk);

        if global_bitplanes.is_empty() {
            global_bitplanes = encrypted.clone();
        } else {
            accumulate_bitplanes(&mut global_bitplanes, &encrypted);
        }
        per_bidder_cts.push(encrypted);
        println!("{name:<7} submits an encrypted bid.");
    }

    println!("Bids are accumulated into encrypted bitplanes.");
    println!("All bids are now locked in encrypted form. Nobody — not even the committee — can see them.");

    act("Act 4 — The Computation");
    println!("The encrypted tally is computed homomorphically across {BID_BITS} bitplanes.");
    println!("The winner is being determined without decrypting any bids...");

    let tally_cts = compute_tallies(
        &global_bitplanes,
        bids.len(),
        &eval_key,
        &relin_key,
        &params,
    );

    let participating = [0usize, 1];
    println!("Two committee members now cooperate for threshold decryption: 1 and 2.");

    let tally_num_cts = tally_cts.len();
    let party_tally_shares: Vec<(usize, Vec<_>)> = participating
        .iter()
        .map(|&i| {
            let smudging = generate_smudging_noise(&params, tally_num_cts);
            let shares =
                compute_decryption_shares(&tally_cts, &sk_poly_sums[i], &smudging, &params);
            (i + 1, shares)
        })
        .collect();

    let tally_pts = threshold_decrypt(&party_tally_shares, &tally_cts, &params);
    let tally_matrix = decode_tally_matrix(&tally_pts, bids.len(), &params);
    let (winner_slot, second_slot) = rank_bidders(&tally_matrix);
    let (winner_name, _) = bids[winner_slot];

    let second_slot = match second_slot {
        Some(s) => s,
        None => {
            println!("Winner: {winner_name}");
            println!("Price to pay: no second price exists.");
            println!("✅ Winner identity: {winner_name}");
            println!("❌ The winning bid amount was never revealed");
            println!("❌ No committee member saw any plaintext bid");
            println!("\n(single bidder — no Vickrey second price)");
            println!("✅ Single-bidder result verified.");
            return;
        }
    };

    let bid_cts = &per_bidder_cts[second_slot];
    let bid_num_cts = bid_cts.len();
    let party_bid_shares: Vec<(usize, Vec<_>)> = participating
        .iter()
        .map(|&i| {
            let smudging = generate_smudging_noise(&params, bid_num_cts);
            let shares = compute_decryption_shares(bid_cts, &sk_poly_sums[i], &smudging, &params);
            (i + 1, shares)
        })
        .collect();

    let bid_pts = threshold_decrypt(&party_bid_shares, bid_cts, &params);
    let second_price = decode_bid(&bid_pts, second_slot, &params);

    println!();
    println!("  ✅ Winner: {winner_name}");
    println!(
        "  ✅ Price to pay (second-highest bid): {}",
        format_eth(second_price)
    );
    println!();
    println!("  ❌ The winning bid amount was never revealed");
    println!("  ❌ No other bid amounts were revealed");
    println!("  ❌ No committee member saw any plaintext bid");

    act("Act 5 — Lifting the Curtain");
    println!("Let's peek behind the scenes to verify the result:");

    let mut shadow: Vec<(usize, u64)> =
        bids.iter().enumerate().map(|(i, &(_, w))| (i, w)).collect();
    shadow.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));

    for (rank, (slot, wei)) in shadow.iter().enumerate() {
        println!("{:>2}. {:<7} {}", rank + 1, bids[*slot].0, format_eth(*wei));
    }

    assert_eq!(winner_slot, shadow[0].0, "winner mismatch");
    assert_eq!(second_slot, shadow[1].0, "second-place mismatch");
    assert_eq!(second_price, shadow[1].1, "Vickrey price mismatch");

    println!(
        "✅ Verified: the FHE auction produced the correct result — without ever seeing the bids."
    );
}
