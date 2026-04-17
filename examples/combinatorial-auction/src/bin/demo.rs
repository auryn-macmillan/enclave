// SPDX-License-Identifier: LGPL-3.0-only

use combinatorial_auction_example::{
    aggregate_public_key, build_config, build_params, encrypt_solver_scores, example_name,
    generate_crp, member_keygen, round1_reference_outcome_fhe, round1_reference_outcome_shadow,
    round2_fairness_filter_fhe, round2_fairness_filter_shadow, settle_auction_fhe,
    settle_auction_shadow, synthetic_directed_pairs, synthetic_public_intents,
    synthetic_solver_bid_tables, AuctionSettlement, BatchedScoreTable, StandaloneScoreTable,
};

fn act(title: &str) {
    println!("\n════════════════════════════════════════════════════════════");
    println!("{title}");
    println!("────────────────────────────────────────────────────────────");
}

fn main() {
    println!("Threshold FHE Fair Combinatorial Auction Demo");
    act("Act 1 — The Problem");
    println!(
        "In a solver competition, every solver wants to reveal just enough to win, but not enough for rivals to learn their strategy."
    );
    println!(
        "This demo shows a fair combinatorial auction where solvers bid on batches of public intents, while their score vectors stay encrypted."
    );
    println!(
        "The public transcript reveals only the reference outcome, the fairness survivors, and then either a winning batched solver or an explicit fallback to the reference outcome."
    );

    let config = build_config();
    let params = build_params();
    let crp = generate_crp(&params);

    act("Act 2 — The Setup");
    println!(
        "Three independent committee members jointly create one BFV public key. No single member can decrypt alone."
    );
    println!(
        "Each solver will pack all 8 directed-pair scores into one ciphertext, so the protocol can compare packed bids with depth-0 subtraction only."
    );
    let committee_members = (0..config.committee_size)
        .map(|_| member_keygen(&params, &crp))
        .collect::<Vec<_>>();
    let public_key = aggregate_public_key(
        committee_members
            .iter()
            .map(|member| member.pk_share.clone())
            .collect(),
    );
    println!(
        "The committee aggregates those shares into one joint public key and uses threshold decryption with 2-of-3 participation. Any value they decrypt becomes public transcript output."
    );

    act("Act 3 — The Submission Phase");
    let directed_pairs = synthetic_directed_pairs();
    let public_intents = synthetic_public_intents(11, 12);
    let (standalone_scores, batched_scores) = build_demo_solver_scores();
    let encrypted_standalone_scores = standalone_scores
        .iter()
        .map(|table| {
            let plaintext =
                combinatorial_auction_example::encode_solver_scores(&table.scores, &params)
                    .expect("encode solver scores");
            encrypt_solver_scores(&plaintext, &public_key)
        })
        .collect::<Vec<_>>();
    let encrypted_batched_scores = batched_scores
        .iter()
        .map(|table| {
            let plaintext =
                combinatorial_auction_example::encode_solver_scores(&table.scores, &params)
                    .expect("encode batched scores");
            encrypt_solver_scores(&plaintext, &public_key)
        })
        .collect::<Vec<_>>();

    println!(
        "Users' intents are public in this model, so solvers can price them in the clear before encrypting their own surplus scores."
    );
    println!(
        "Each solver submits one ciphertext containing 8 packed scores — one for each directed trading pair."
    );

    let shadow_round1 = round1_reference_outcome_shadow(&standalone_scores).expect("shadow round1");
    let fhe_round1 = round1_reference_outcome_fhe(
        &encrypted_standalone_scores,
        &committee_members,
        &[0, 1],
        &params,
    )
    .expect("fhe round1");
    assert_eq!(fhe_round1, shadow_round1, "Round 1 mismatch");

    let shadow_round2 =
        round2_fairness_filter_shadow(&standalone_scores, &batched_scores).expect("shadow round2");
    let fhe_round2 = round2_fairness_filter_fhe(
        &encrypted_standalone_scores,
        &encrypted_batched_scores,
        &committee_members,
        &[0, 1],
        &params,
    )
    .expect("fhe round2");
    assert_eq!(fhe_round2, shadow_round2, "Round 2 mismatch");

    let shadow_settlement =
        settle_auction_shadow(&standalone_scores, &batched_scores).expect("shadow settlement");
    let fhe_settlement = settle_auction_fhe(
        &encrypted_standalone_scores,
        &encrypted_batched_scores,
        &committee_members,
        &[0, 1],
        &params,
    )
    .expect("fhe settlement");
    assert_eq!(fhe_settlement, shadow_settlement, "Settlement mismatch");

    println!(
        "{} demo: {} directed pairs, {} solvers, committee size {}",
        example_name(),
        config.num_pairs,
        config.num_solvers,
        config.committee_size
    );
    println!("\n== Setup summary ==");
    println!(
        "Built joint public key from {} committee members; encrypted {} standalone tables and {} batched tables.",
        committee_members.len(),
        encrypted_standalone_scores.len(),
        encrypted_batched_scores.len()
    );

    println!("\n== Public synthetic intents ==");
    println!("Directed pairs:");
    for pair in directed_pairs {
        println!(
            "  pair {:>2}: token {} / token {} {:?}",
            pair.pair_index,
            pair.token_pair.base_token,
            pair.token_pair.quote_token,
            pair.direction
        );
    }
    println!("Public intents:");
    for intent in &public_intents {
        println!(
            "  user {:>2}: pair {:>2}, qty {:>2}, limit {}",
            intent.user_id, intent.pair.pair_index, intent.quantity, intent.limit_price
        );
    }

    println!("\n== Solver score context ==");
    for (standalone_table, batched_table) in standalone_scores.iter().zip(&batched_scores) {
        println!(
            "  solver {:>2}: standalone {:?} | batched {:?}",
            standalone_table.solver_id, standalone_table.scores, batched_table.scores
        );
    }

    act("Act 4 — The Public Computation");
    println!(
        "The protocol now performs progressive public decryption. The committee jointly produces decryption shares, and every authorized decryption becomes part of the public transcript."
    );
    println!(
        "Round 1 finds the best standalone solver on each pair. Round 2 checks whether any batched solver beats that reference on every pair."
    );
    println!(
        "If at least one batched solver survives, later rounds pick the best survivor and compute the second price. Otherwise the protocol falls back to the reference outcome."
    );

    println!("\n== Round 1 reference outcome ==");
    println!(
        "The protocol publicly reveals pair-by-pair comparison outcomes until it can identify the best standalone solver on each directed pair."
    );
    println!(
        "Reference winner per pair: {:?}",
        shadow_round1.winner_solver_indices
    );
    println!("Shadow verification passed: Round 1");

    println!("\n== Round 2 fairness filter ==");
    println!(
        "Now the protocol publicly reveals whether each batched solver matches or beats the reference outcome on every pair. A solver survives only if it never falls below the reference."
    );
    if shadow_round2.fallback_to_reference {
        println!("No fair batched solver survived. Fallback to Round 1 reference outcome.");
    } else {
        println!("Survivors: {:?}", shadow_round2.survivors);
        println!(
            "The default fixture is tuned so a batched winner can improve on the standalone baseline without violating fairness."
        );
    }
    println!("Shadow verification passed: Round 2");

    println!("\n== Settlement ==");
    match shadow_settlement {
        AuctionSettlement::ReferenceFallback { reference_outcome } => {
            println!("\n== Round 3 winner selection ==");
            println!("Shadow verification passed: Round 3");
            println!(
                "Because no batched solver cleared the fairness bar, there is no winner-selection race to run."
            );
            println!("Skipped: no fair batched solver survived Round 2.");
            println!("\n== Round 4 second-price reward ==");
            println!("Shadow verification passed: Round 4");
            println!(
                "Without a batched winner, there is no runner-up price to reveal. The protocol simply publishes the reference outcome."
            );
            println!("Skipped: no batched winner was selected.");
            println!("\n== Final settlement transcript ==");
            println!("Shadow verification passed: Settlement");
            println!(
                "Fallback branch: using Round 1 reference outcome with winners {:?}.",
                reference_outcome.winner_solver_indices
            );
        }
        AuctionSettlement::BatchedWinner {
            winner_solver_index,
            second_price,
            runner_up_solver_index,
            ..
        } => {
            println!("\n== Round 3 winner selection ==");
            println!("Shadow verification passed: Round 3");
            println!(
                "The protocol publicly reveals enough survivor-to-survivor comparison output to identify the batched solver with the highest total packed score."
            );
            println!("Winner solver index: {}", winner_solver_index);
            println!("\n== Round 4 second-price reward ==");
            println!("Shadow verification passed: Round 4");
            println!(
                "The winner pays the runner-up total score, so the protocol publicly reveals only the runner-up price needed for settlement."
            );
            if let Some(runner_up_solver_index) = runner_up_solver_index {
                println!("Runner-up solver index: {}", runner_up_solver_index);
            } else {
                println!("Runner-up solver index: none (single survivor branch)");
            }
            println!("Second price: {}", second_price);
            println!("\n== Final settlement transcript ==");
            println!("Shadow verification passed: Settlement");
            println!(
                "Final outcome: the batched winner is public, the second price is public, and losing score vectors remain encrypted."
            );
        }
    }

    act("Act 5 — What Was Revealed");
    println!("The public transcript revealed:");
    println!("  1. The best standalone solver for each directed pair.");
    println!("  2. Which batched solvers passed the fairness filter.");
    println!("  3. Either a winning batched solver and second price, or an explicit fallback to the reference outcome.");
    println!("It did not reveal full losing score vectors or every solver's exact strategy on every pair.");
}

fn build_demo_solver_scores() -> (Vec<StandaloneScoreTable>, Vec<BatchedScoreTable>) {
    let (mut standalone_tables, mut batched_tables) = synthetic_solver_bid_tables(29);

    for table in standalone_tables.iter_mut().skip(3) {
        table.scores = [95, 95, 95, 95, 95, 95, 95, 95];
    }
    for table in batched_tables.iter_mut().skip(5) {
        table.scores = [120, 120, 120, 120, 120, 120, 120, 120];
    }

    standalone_tables[0].scores = [100, 180, 130, 160, 120, 170, 140, 150];
    standalone_tables[1].scores = [150, 120, 180, 130, 170, 110, 190, 100];
    standalone_tables[2].scores = [130, 170, 120, 190, 110, 180, 100, 200];

    batched_tables[0].scores = [155, 185, 182, 195, 172, 184, 193, 205];
    batched_tables[1].scores = [150, 180, 180, 190, 170, 180, 190, 201];
    batched_tables[2].scores = [149, 180, 180, 190, 170, 180, 190, 205];
    batched_tables[3].scores = [120, 150, 120, 150, 120, 150, 120, 150];
    batched_tables[4].scores = [110, 140, 110, 140, 110, 140, 110, 140];

    (standalone_tables, batched_tables)
}
