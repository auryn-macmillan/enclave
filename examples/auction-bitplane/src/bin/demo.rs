// SPDX-License-Identifier: LGPL-3.0-only
//
//! # Vickrey Sealed-Bid Auction Demo (Threshold FHE)
//!
//! Generates 10 random bids, runs the full threshold FHE pipeline
//! (committee DKG → encrypt → accumulate → tally → threshold decrypt →
//! rank), then verifies the result against a plaintext shadow.

use auction_bitplane_example::{
    accumulate_bitplanes, aggregate_public_key, aggregate_sk_shares_for_party,
    build_eval_key_from_committee, build_params, compute_decryption_shares, compute_tallies,
    decode_bid, decode_tally_matrix, encode_bid_into_planes, encrypt_bitplanes, generate_crp,
    generate_smudging_noise, member_keygen, rank_bidders, threshold_decrypt, BID_BITS, COMMITTEE_N,
    SLOTS, THRESHOLD,
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
    format!("{whole}.{frac:018} ETH")
}

fn main() {
    println!("=== Vickrey Bit-Plane Auction Demo (2-of-3 Threshold) ===\n");

    // ── BFV parameters ───────────────────────────────────────────────────
    let params = build_params();
    println!(
        "BFV parameters: N={}, t={}, {} moduli, {} bitplanes\n",
        params.degree(),
        params.plaintext(),
        params.moduli().len(),
        BID_BITS,
    );

    // ── Committee DKG ────────────────────────────────────────────────────
    //
    // Three committee members each generate a secret key, a public key
    // share, and Shamir secret shares of their secret key.  No trusted
    // dealer is involved.
    println!(
        "Committee DKG ({COMMITTEE_N} members, threshold {}):",
        THRESHOLD + 1
    );
    let crp = generate_crp(&params);
    let members: Vec<_> = (0..COMMITTEE_N)
        .map(|i| {
            let m = member_keygen(&params, &crp);
            println!("  Member {i}: key share generated, Shamir shares distributed");
            m
        })
        .collect();

    // Aggregate public key shares into a joint public key.
    let pk_shares: Vec<_> = members.iter().map(|m| m.pk_share.clone()).collect();
    let joint_pk = aggregate_public_key(pk_shares);
    println!("  → Joint public key aggregated\n");

    // Each member aggregates the Shamir shares they received from others
    // into their secret-key polynomial sum (used for threshold decryption).
    let all_sk_shares: Vec<_> = members.iter().map(|m| m.sk_shares.clone()).collect();
    let sk_poly_sums: Vec<_> = (0..COMMITTEE_N)
        .map(|i| aggregate_sk_shares_for_party(&all_sk_shares, i, &params))
        .collect();

    // ── Eval key (demo shortcut) ─────────────────────────────────────────
    //
    // The eval and relin keys require a full secret key, for which no MPC
    // protocol exists in this library.  We temporarily reconstruct it from
    // the committee's raw secret keys, build the keys, and discard the
    // reconstructed secret.  See README for production considerations.
    let member_sk_refs: Vec<&_> = members.iter().map(|m| &m.sk).collect();
    let (eval_key, relin_key) = build_eval_key_from_committee(&member_sk_refs, &params);
    println!("Eval key built (demo shortcut — see README)\n");

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

    // ── Encode, encrypt (with joint PK), accumulate ──────────────────────
    let mut global_bitplanes: Vec<Ciphertext> = Vec::new();
    let mut per_bidder_cts: Vec<Vec<Ciphertext>> = Vec::new();

    for (slot, &(_, wei)) in bids.iter().enumerate() {
        let planes = encode_bid_into_planes(wei, slot, &params);
        let encrypted = encrypt_bitplanes(&planes, &joint_pk);

        if global_bitplanes.is_empty() {
            global_bitplanes = encrypted.clone();
        } else {
            accumulate_bitplanes(&mut global_bitplanes, &encrypted);
        }
        per_bidder_cts.push(encrypted);
    }

    // ── FHE tally ────────────────────────────────────────────────────────
    let tally_cts = compute_tallies(
        &global_bitplanes,
        bids.len(),
        &eval_key,
        &relin_key,
        &params,
    );
    println!("\nFHE tally computed ({BID_BITS} bitplanes)\n");

    // ── Threshold decrypt tallies (2-of-3) ───────────────────────────────
    //
    // Members 0 and 1 participate.  Each generates smudging noise and
    // computes decryption shares for the tally ciphertexts.
    let participating = [0usize, 1];
    println!("Threshold decryption: members {:?} (2-of-3)", participating);

    let tally_num_cts = tally_cts.len();
    let party_tally_shares: Vec<(usize, Vec<_>)> = participating
        .iter()
        .map(|&i| {
            let smudging = generate_smudging_noise(&params, tally_num_cts);
            let shares =
                compute_decryption_shares(&tally_cts, &sk_poly_sums[i], &smudging, &params);
            // Party IDs are 1-based for Shamir reconstruction.
            (i + 1, shares)
        })
        .collect();

    let tally_pts = threshold_decrypt(&party_tally_shares, &tally_cts, &params);
    let tally_matrix = decode_tally_matrix(&tally_pts, bids.len(), &params);
    let (winner_slot, second_slot) = rank_bidders(&tally_matrix);

    let (winner_name, _) = bids[winner_slot];
    println!("  Winner: {winner_name} (slot {winner_slot})");

    // ── Threshold decrypt the Vickrey (second) price ─────────────────────
    let second_slot = second_slot.expect("expected at least two bidders");
    let (second_name, _) = bids[second_slot];

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
    println!(
        "  Vickrey price: {} (from {second_name}, slot {second_slot})",
        format_eth(second_price),
    );

    // ── Plaintext shadow verification ────────────────────────────────────
    let mut shadow: Vec<(usize, u64)> =
        bids.iter().enumerate().map(|(i, &(_, w))| (i, w)).collect();
    shadow.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));

    assert_eq!(winner_slot, shadow[0].0, "winner mismatch");
    assert_eq!(second_slot, shadow[1].0, "second-place mismatch");
    assert_eq!(second_price, shadow[1].1, "Vickrey price mismatch");

    println!("\n✅ Verified: FHE ranking matches plaintext shadow.");
}
