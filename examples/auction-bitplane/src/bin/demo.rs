// SPDX-License-Identifier: LGPL-3.0-only

use auction_bitplane_example::{
    accumulate_bid, aggregate_public_key, aggregate_sk_shares_for_party, build_curve_bucket_mask,
    build_eval_key_from_committee, build_params, build_price_ladder, build_top_bucket_mask,
    compute_decryption_shares, compute_pair_curve, decode_curve_bucket_presence_plaintext,
    decode_top_bucket_signal, encode_bid, encrypt_bid, find_second_price_bucket_progressive,
    find_top_bucket_progressive, generate_crp, generate_eval_key_root_seed,
    generate_smudging_noise, identify_top_bucket_winner, identify_unique_bucket_winner,
    mask_top_bucket, member_keygen, resolve_progressive_vickrey_outcome, threshold_decrypt,
    COMMITTEE_N,
};
use fhe::bfv::Ciphertext;

fn act(title: &str) {
    println!("\n════════════════════════════════════════════════════════════");
    println!("{title}");
    println!("────────────────────────────────────────────────────────────");
}

fn main() {
    println!("Threshold FHE Discrete-Ladder Vickrey Auction Demo");

    act("Act 1 — The Problem");
    println!("A classic Vickrey auction should reveal who won and what they pay, but not how much more the winner would have paid.");
    println!("This demo maps bids onto a public price ladder and makes only authorized decryptions public.");
    println!("The public transcript reveals the second-price bucket first, then only the minimum extra information needed to identify the winner.");

    let params = build_params();
    let price_ladder = build_price_ladder(100, 500, 9);

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

    let joint_pk = aggregate_public_key(members.iter().map(|m| m.pk_share.clone()).collect());
    println!("The committee aggregates those shares into one joint public key.");

    let all_sk_shares: Vec<_> = members.iter().map(|m| m.sk_shares.clone()).collect();
    let sk_poly_sums: Vec<_> = (0..COMMITTEE_N)
        .map(|i| aggregate_sk_shares_for_party(&all_sk_shares, i, &params))
        .collect();

    let member_sk_refs: Vec<&_> = members.iter().map(|m| &m.sk).collect();
    let eval_key_root_seed = generate_eval_key_root_seed();
    let (_eval_key, relin_key) =
        build_eval_key_from_committee(&member_sk_refs, &params, &eval_key_root_seed);
    println!("The committee also derives distributed evaluation keys without reconstructing the joint secret key.");

    act("Act 3 — The Bids");
    let bids = vec![
        ("Alice", 250u64),
        ("Bob", 500),
        ("Charlie", 400),
        ("Dave", 200),
        ("Eve", 350),
    ];

    let mut per_bidder_cts: Vec<Ciphertext> = Vec::new();
    let mut aggregate_ct: Option<Ciphertext> = None;

    for (submission_order, &(name, price)) in bids.iter().enumerate() {
        let pt = encode_bid(price, submission_order, &price_ladder, &params);
        let ct = encrypt_bid(&pt, &joint_pk);
        if let Some(global) = aggregate_ct.as_mut() {
            accumulate_bid(global, &ct);
        } else {
            aggregate_ct = Some(ct.clone());
        }
        per_bidder_cts.push(ct);
        println!("{name:<7} submits an encrypted bid at ladder price {price} (submission order {submission_order}).");
    }

    println!("Each bidder encrypts a single ciphertext encoding cumulative willingness-to-pay over the public ladder.");

    act("Act 4 — Progressive Public Decryption");
    println!("First, the committee decrypts pair-indicator buckets from the top down until it finds the second-price bucket.");

    let aggregate_ct = aggregate_ct.expect("at least one bid");
    let participating = [0usize, 1usize];
    let pair_curve = compute_pair_curve(&aggregate_ct, price_ladder.len(), &relin_key, &params);
    let mut pair_bucket_reveals = Vec::new();
    let second = find_second_price_bucket_progressive(&price_ladder, |level_idx| {
        let mask = build_curve_bucket_mask(level_idx, &params);
        let masked = vec![&pair_curve * &mask];
        let shares: Vec<(usize, Vec<_>)> = participating
            .iter()
            .map(|&i| {
                let smudging = generate_smudging_noise(&params, 1);
                let shares =
                    compute_decryption_shares(&masked, &sk_poly_sums[i], &smudging, &params);
                (i + 1, shares)
            })
            .collect();
        let pt = threshold_decrypt(&shares, &masked, &params)
            .into_iter()
            .next()
            .expect("pair bucket plaintext");
        let present = decode_curve_bucket_presence_plaintext(&pt, level_idx, &params);
        pair_bucket_reveals.push((level_idx, present));
        present
    });
    let (second_bucket, second_price) = match second {
        Some((bucket, price)) => (Some(bucket), Some(price)),
        None => (None, None),
    };

    println!(
        "Revealed pair-indicator buckets (high to low until stop): {:?}",
        pair_bucket_reveals
    );

    let mut occupancy_bucket_reveals = Vec::new();
    let (top_bucket, top_price) =
        find_top_bucket_progressive(&price_ladder, second_bucket, |level_idx| {
            let mask = build_curve_bucket_mask(level_idx, &params);
            let masked = vec![&aggregate_ct * &mask];
            let shares: Vec<(usize, Vec<_>)> = participating
                .iter()
                .map(|&i| {
                    let smudging = generate_smudging_noise(&params, 1);
                    let shares =
                        compute_decryption_shares(&masked, &sk_poly_sums[i], &smudging, &params);
                    (i + 1, shares)
                })
                .collect();
            let pt = threshold_decrypt(&shares, &masked, &params)
                .into_iter()
                .next()
                .expect("curve bucket plaintext");
            let present = decode_curve_bucket_presence_plaintext(&pt, level_idx, &params);
            occupancy_bucket_reveals.push((level_idx, present));
            present
        })
        .expect("top bucket");

    println!(
        "Additional occupancy bucket reveals above the second-price bucket: {:?}",
        occupancy_bucket_reveals
    );
    println!(
        "These reveals identify the price bucket where a second bidder is present ({}). The winner-identification step only needs the next ladder step above that bucket.",
        second_price.map_or("none".to_string(), |p| p.to_string())
    );

    let reveal_bucket = if second_bucket == Some(top_bucket) {
        println!(
            "The top bucket contains multiple bidders. The earliest submission at price {} wins.",
            top_price
        );
        top_bucket
    } else {
        let reveal_bucket = second_bucket
            .map(|bucket| bucket + 1)
            .expect("strict-winner path requires second-price bucket");
        println!(
            "There's a unique bidder above the second-price bucket. Only bidder presence at the next ladder step ({}) is revealed to confirm the winner.",
            price_ladder[reveal_bucket]
        );
        reveal_bucket
    };

    println!("The committee now performs a targeted threshold decryption of bucket {reveal_bucket} for each bidder.");

    let presence_mask = build_curve_bucket_mask(reveal_bucket, &params);
    let masked_presence_cts: Vec<Ciphertext> = per_bidder_cts
        .iter()
        .map(|ct| mask_top_bucket(ct, &presence_mask))
        .collect();
    let presence_party_shares: Vec<(usize, Vec<_>)> = participating
        .iter()
        .map(|&i| {
            let smudging = generate_smudging_noise(&params, masked_presence_cts.len());
            let shares = compute_decryption_shares(
                &masked_presence_cts,
                &sk_poly_sums[i],
                &smudging,
                &params,
            );
            (i + 1, shares)
        })
        .collect();
    let presence_pts = threshold_decrypt(&presence_party_shares, &masked_presence_cts, &params);
    let presence: Vec<bool> = presence_pts
        .iter()
        .map(|pt| decode_curve_bucket_presence_plaintext(pt, reveal_bucket, &params))
        .collect();

    let winner_idx = if let Some(idx) = identify_unique_bucket_winner(&presence) {
        println!(
            "Winner identified by targeted reveal at price {}: {}.",
            price_ladder[reveal_bucket], bids[idx].0
        );
        idx
    } else {
        println!(
            "Multiple bidders at price {}. Identifying the earliest submission.",
            top_price
        );
        let mask = build_top_bucket_mask(reveal_bucket, &params);
        let masked_bidder_cts: Vec<Ciphertext> = per_bidder_cts
            .iter()
            .map(|ct| mask_top_bucket(ct, &mask))
            .collect();
        let bidder_party_shares: Vec<(usize, Vec<_>)> = participating
            .iter()
            .map(|&i| {
                let smudging = generate_smudging_noise(&params, masked_bidder_cts.len());
                let shares = compute_decryption_shares(
                    &masked_bidder_cts,
                    &sk_poly_sums[i],
                    &smudging,
                    &params,
                );
                (i + 1, shares)
            })
            .collect();
        let bidder_plaintexts =
            threshold_decrypt(&bidder_party_shares, &masked_bidder_cts, &params);
        let signals: Vec<_> = bidder_plaintexts
            .iter()
            .map(|pt| decode_top_bucket_signal(pt, reveal_bucket, &params))
            .collect();
        identify_top_bucket_winner(&signals).expect("winner")
    };

    let outcome = resolve_progressive_vickrey_outcome(
        winner_idx,
        &price_ladder,
        second_bucket,
        reveal_bucket,
    )
    .expect("outcome");

    act("Act 5 — Public Outcome");
    println!("Winner: {}", bids[winner_idx].0);
    match second_price {
        Some(price) => println!("Clearing price (Vickrey): {price}"),
        None => println!("Clearing price: none (only one bidder)"),
    }
    println!(
        "Winner-identification reveal bucket price: {}",
        price_ladder[reveal_bucket]
    );
    println!(
        "Outcome summary: winner bidder index {}, second-price bucket {:?}, tie at top {}.",
        outcome.winner_bidder, outcome.second_price_bucket, outcome.top_tie
    );
    println!("What stayed hidden: individual bid amounts and how much higher the winner was willing to go.");

    let mut shadow: Vec<(usize, u64, usize)> = bids
        .iter()
        .enumerate()
        .map(|(submission_order, &(_, price))| (submission_order, price, submission_order))
        .collect();
    shadow.sort_by(|a, b| b.1.cmp(&a.1).then(a.2.cmp(&b.2)));
    let expected_winner = shadow[0].0;
    let expected_second_price = if shadow.len() >= 2 {
        Some(shadow[1].1)
    } else {
        None
    };

    assert_eq!(winner_idx, expected_winner, "winner mismatch");
    assert_eq!(second_price, expected_second_price, "second price mismatch");

    println!("✅ Verified: the discrete-ladder threshold FHE auction produced the correct winner and second price.");
}
