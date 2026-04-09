// SPDX-License-Identifier: LGPL-3.0-only
//

use auction_bitplane_example::{
    accumulate_bitplanes, build_eval_key, build_params, build_relin_key,
    decrypt_bid_from_bitplanes, encode_bid_into_planes, encrypt_bitplanes_sk, find_winner_bitplane,
    BID_BITS,
};
use fhe::bfv::{Ciphertext, SecretKey};
use rand::rngs::OsRng;

fn main() {
    println!("=== Sealed-Bid Vickrey Auction (Horizontal BFV SIMD) ===\n");

    let params = build_params();
    let mut rng = OsRng;
    let sk = SecretKey::random(&params, &mut rng);
    let eval_key = build_eval_key(&sk);
    let relin_key = build_relin_key(&sk);

    println!(
        "Parameters: N={}, t={}, L={} moduli",
        params.degree(),
        params.plaintext(),
        params.moduli().len()
    );
    println!("Bid range: 0 to u64::MAX ({} bits)\n", BID_BITS);

    let bidders = [("Alice", 750u64), ("Bob", 500u64), ("Charlie", 900u64)];

    let mut global_bitplanes: Option<Vec<Ciphertext>> = None;
    let mut per_bidder_cts: Vec<Vec<Ciphertext>> = Vec::with_capacity(bidders.len());

    for (slot, (name, value)) in bidders.iter().enumerate() {
        let planes = encode_bid_into_planes(*value, slot, &params);
        let contribution = encrypt_bitplanes_sk(&planes, &sk);

        if let Some(global) = global_bitplanes.as_mut() {
            accumulate_bitplanes(global, &contribution);
        } else {
            global_bitplanes = Some(contribution.clone());
        }
        per_bidder_cts.push(contribution);

        println!("slot {slot}: {name} bid {value}");
    }

    let global_bitplanes = global_bitplanes.expect("at least one bidder is required");
    let (winner_slot, second_slot) = find_winner_bitplane(
        &global_bitplanes,
        bidders.len(),
        &eval_key,
        &relin_key,
        &sk,
        &params,
    );

    println!(
        "\nWinner: {} (slot {})",
        bidders[winner_slot].0, winner_slot
    );

    let second_slot = second_slot.expect("expected a second-ranked bidder");
    let second_price =
        decrypt_bid_from_bitplanes(&per_bidder_cts[second_slot], second_slot, &sk, &params);
    println!(
        "Vickrey price: {} (decrypted from slot {}, {})",
        second_price, second_slot, bidders[second_slot].0
    );

    assert_eq!(winner_slot, 2, "winner should be Charlie (slot 2)");
    assert_eq!(second_slot, 0, "second should be Alice (slot 0)");
    assert_eq!(second_price, 750, "Vickrey price should be 750");

    println!("✅ Vickrey auction verified.");
}
