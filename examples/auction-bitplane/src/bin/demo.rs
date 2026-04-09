// SPDX-License-Identifier: LGPL-3.0-only
//
//! Vickrey sealed-bid auction demo using FHE bit-plane tallying.
//!
//! Generates 10 random bids, runs the full FHE pipeline (encode → encrypt →
//! accumulate → tally → rank), then verifies the result against a plaintext
//! shadow computation.

use auction_bitplane_example::{
    accumulate_bitplanes, build_eval_key, build_params, build_relin_key, decrypt_bid,
    encode_bid_into_planes, encrypt_bitplanes, find_winner, BID_BITS, SLOTS,
};
use fhe::bfv::{Ciphertext, SecretKey};
use rand::rngs::OsRng;
use rand::Rng;

const NAMES: [&str; 10] = [
    "Alice", "Bob", "Charlie", "Dave", "Eve", "Frank", "Grace", "Heidi", "Ivan", "Judy",
];

/// Format a raw `u64` wei value as `"whole.fractional ETH"`.
fn format_eth(wei: u64) -> String {
    let whole = wei / 1_000_000_000_000_000_000;
    let frac = wei % 1_000_000_000_000_000_000;
    format!("{whole}.{frac:018} ETH")
}

fn main() {
    println!("=== Vickrey Bit-Plane Auction Demo ===\n");

    // ── Setup ────────────────────────────────────────────────────────────
    let params = build_params();
    let sk = SecretKey::random(&params, &mut OsRng);
    let eval_key = build_eval_key(&sk);
    let relin_key = build_relin_key(&sk);

    println!(
        "BFV parameters: N={}, t={}, {} moduli, {} bitplanes\n",
        params.degree(),
        params.plaintext(),
        params.moduli().len(),
        BID_BITS,
    );

    // ── Generate random bids ─────────────────────────────────────────────
    let bids: Vec<(&str, u64)> = NAMES
        .iter()
        .map(|name| (*name, OsRng.gen::<u64>()))
        .collect();

    assert!(bids.len() <= SLOTS, "too many bidders for SIMD slots");

    println!("Bidders:");
    for (slot, (name, wei)) in bids.iter().enumerate() {
        println!("  slot {slot:>2}  {name:<10} {}", format_eth(*wei));
    }

    // ── Encode, encrypt, accumulate ──────────────────────────────────────
    let mut global_bitplanes: Vec<Ciphertext> = Vec::new();
    let mut per_bidder_cts: Vec<Vec<Ciphertext>> = Vec::new();

    for (slot, &(_, wei)) in bids.iter().enumerate() {
        let planes = encode_bid_into_planes(wei, slot, &params);
        let encrypted = encrypt_bitplanes(&planes, &sk);

        if global_bitplanes.is_empty() {
            global_bitplanes = encrypted.clone();
        } else {
            accumulate_bitplanes(&mut global_bitplanes, &encrypted);
        }
        per_bidder_cts.push(encrypted);
    }

    // ── FHE tally + ranking ──────────────────────────────────────────────
    let (winner_slot, second_slot) = find_winner(
        &global_bitplanes,
        bids.len(),
        &eval_key,
        &relin_key,
        &sk,
        &params,
    );

    let (winner_name, _) = bids[winner_slot];
    println!("\nFHE result: winner = {winner_name} (slot {winner_slot})");

    // ── Decrypt and verify the Vickrey (second) price ────────────────────
    let second_slot = second_slot.expect("expected at least two bidders");
    let second_price = decrypt_bid(&per_bidder_cts[second_slot], second_slot, &sk, &params);
    let (second_name, _) = bids[second_slot];
    println!(
        "Vickrey price: {} (from {second_name}, slot {second_slot})",
        format_eth(second_price),
    );

    // ── Plaintext shadow: sort bids descending, tie-break by slot ────────
    let mut shadow: Vec<(usize, u64)> =
        bids.iter().enumerate().map(|(i, &(_, w))| (i, w)).collect();
    shadow.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));

    assert_eq!(winner_slot, shadow[0].0, "winner mismatch");
    assert_eq!(second_slot, shadow[1].0, "second-place mismatch");
    assert_eq!(second_price, shadow[1].1, "Vickrey price mismatch");

    println!("\n✅ Verified: FHE ranking matches plaintext shadow.");
}
