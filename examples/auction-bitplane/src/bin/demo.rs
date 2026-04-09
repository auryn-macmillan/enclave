// SPDX-License-Identifier: LGPL-3.0-only
//
use auction_bitplane_example::{
    accumulate_bitplanes, build_eval_key, build_params, build_relin_key,
    decrypt_bid_from_bitplanes, encode_bid_into_planes, encrypt_bitplanes_sk, find_winner_bitplane,
    BID_BITS, SLOTS,
};
use fhe::bfv::{Ciphertext, SecretKey};
use rand::rngs::OsRng;
use rand::Rng;

struct EtherValue(u64);

impl EtherValue {
    fn to_display_string(&self) -> String {
        let whole = self.0 / 1_000_000_000_000_000_000;
        let fractional = self.0 % 1_000_000_000_000_000_000;
        format!("{whole}.{fractional:018}")
    }

    fn to_u64(&self) -> u64 {
        self.0
    }
}

fn main() {
    println!("=== Vickrey Bit-Plane Auction Demo ===\n");

    let params = build_params();
    let mut rng = OsRng;
    let sk = SecretKey::random(&params, &mut rng);
    let eval_key = build_eval_key(&sk);
    let relin_key = build_relin_key(&sk);

    let names = [
        "Alice", "Bob", "Charlie", "Dave", "Eve", "Frank", "Grace", "Heidi", "Ivan", "Judy",
    ];
    let bidders: Vec<(String, EtherValue)> = names
        .iter()
        .map(|name| ((*name).to_string(), EtherValue(rng.gen::<u64>())))
        .collect();
    let n_bidders = bidders.len();

    assert!(
        n_bidders <= SLOTS,
        "too many bidders for available SIMD slots"
    );

    println!(
        "Parameters: N={}, t={}, L={} moduli",
        params.degree(),
        params.plaintext(),
        params.moduli().len()
    );
    println!("Bid range: 0 to u64::MAX ({} bits)\n", BID_BITS);

    println!("Generated bidder values:");
    for (slot, (name, value)) in bidders.iter().enumerate() {
        println!(
            "  slot {slot:>2}  {:<10} {} ETH",
            name,
            value.to_display_string()
        );
    }

    let mut global_bitplanes: Option<Vec<Ciphertext>> = None;
    let mut per_bidder_cts: Vec<Vec<Ciphertext>> = Vec::with_capacity(n_bidders);

    for (slot, (_, value)) in bidders.iter().enumerate() {
        let planes = encode_bid_into_planes(value.to_u64(), slot, &params);
        let contribution = encrypt_bitplanes_sk(&planes, &sk);

        if let Some(global) = global_bitplanes.as_mut() {
            accumulate_bitplanes(global, &contribution);
        } else {
            global_bitplanes = Some(contribution.clone());
        }
        per_bidder_cts.push(contribution);
    }

    let global_bitplanes = global_bitplanes.expect("at least one bidder is required");
    debug_assert_eq!(global_bitplanes.len(), BID_BITS);

    let (winner_slot, second_slot) = find_winner_bitplane(
        &global_bitplanes,
        n_bidders,
        &eval_key,
        &relin_key,
        &sk,
        &params,
    );

    println!(
        "\nFHE winner: {} (slot {})",
        bidders[winner_slot].0, winner_slot
    );

    let second_price = second_slot.map(|slot| {
        let price = decrypt_bid_from_bitplanes(&per_bidder_cts[slot], slot, &sk, &params);
        println!(
            "Vickrey price: {} wei (decrypted from slot {})",
            price, slot
        );
        (slot, price)
    });

    let mut shadow = bidders
        .iter()
        .enumerate()
        .map(|(slot, (_, value))| (slot, value.to_u64()))
        .collect::<Vec<_>>();
    shadow.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    assert_eq!(winner_slot, shadow[0].0, "winner slot mismatch");

    if let Some((slot, price)) = second_price {
        assert_eq!(slot, shadow[1].0, "second slot mismatch");
        assert_eq!(price, shadow[1].1, "second price mismatch");
    }

    println!("\n✅ Vickrey auction verified against plaintext shadow.");
}
