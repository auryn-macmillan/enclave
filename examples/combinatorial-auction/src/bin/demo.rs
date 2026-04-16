// SPDX-License-Identifier: LGPL-3.0-only

use combinatorial_auction_example::{
    aggregate_public_key, build_config, build_params, encrypt_solver_scores, example_name,
    generate_crp, member_keygen, round1_reference_outcome_fhe, round1_reference_outcome_shadow,
    round2_fairness_filter_fhe, round2_fairness_filter_shadow, settle_auction_fhe,
    settle_auction_shadow, synthetic_directed_pairs, synthetic_public_intents,
    synthetic_solver_score_tables, AuctionSettlement, SolverScoreTable,
};

fn main() {
    let config = build_config();
    let params = build_params();
    let crp = generate_crp(&params);
    let committee_members = (0..config.committee_size)
        .map(|_| member_keygen(&params, &crp))
        .collect::<Vec<_>>();
    let public_key = aggregate_public_key(
        committee_members
            .iter()
            .map(|member| member.pk_share.clone())
            .collect(),
    );

    let directed_pairs = synthetic_directed_pairs();
    let public_intents = synthetic_public_intents(11, 12);
    let solver_scores = build_demo_solver_scores();
    let encrypted_scores = solver_scores
        .iter()
        .map(|table| {
            let plaintext =
                combinatorial_auction_example::encode_solver_scores(&table.scores, &params)
                    .expect("encode solver scores");
            encrypt_solver_scores(&plaintext, &public_key)
        })
        .collect::<Vec<_>>();

    let shadow_round1 = round1_reference_outcome_shadow(&solver_scores).expect("shadow round1");
    let fhe_round1 =
        round1_reference_outcome_fhe(&encrypted_scores, &committee_members, &[0, 1], &params)
            .expect("fhe round1");
    assert_eq!(fhe_round1, shadow_round1, "Round 1 mismatch");

    let shadow_round2 = round2_fairness_filter_shadow(&solver_scores).expect("shadow round2");
    let fhe_round2 =
        round2_fairness_filter_fhe(&encrypted_scores, &committee_members, &[0, 1], &params)
            .expect("fhe round2");
    assert_eq!(fhe_round2, shadow_round2, "Round 2 mismatch");

    let shadow_settlement = settle_auction_shadow(&solver_scores).expect("shadow settlement");
    let fhe_settlement =
        settle_auction_fhe(&encrypted_scores, &committee_members, &[0, 1], &params)
            .expect("fhe settlement");
    assert_eq!(fhe_settlement, shadow_settlement, "Settlement mismatch");

    println!(
        "{} demo: {} directed pairs, {} solvers, committee size {}",
        example_name(),
        config.num_pairs,
        config.num_solvers,
        config.committee_size
    );
    println!("\n== DKG setup ==");
    println!(
        "Built joint public key from {} committee members; encrypted {} solver score tables.",
        committee_members.len(),
        encrypted_scores.len()
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
    for table in &solver_scores {
        println!("  solver {:>2}: {:?}", table.solver_id, table.scores);
    }

    println!("\n== Round 1 reference outcome ==");
    println!(
        "Reference winner per pair: {:?}",
        shadow_round1.winner_solver_indices
    );
    println!("Shadow verification passed: Round 1");

    println!("\n== Round 2 fairness filter ==");
    if shadow_round2.fallback_to_reference {
        println!("No fair batched solver survived. Fallback to Round 1 reference outcome.");
    } else {
        println!("Survivors: {:?}", shadow_round2.survivors);
    }
    println!("Shadow verification passed: Round 2");

    println!("\n== Settlement ==");
    match shadow_settlement {
        AuctionSettlement::ReferenceFallback { reference_outcome } => {
            println!("\n== Round 3 winner selection ==");
            println!("Shadow verification passed: Round 3");
            println!("Skipped: no fair batched solver survived Round 2.");
            println!("\n== Round 4 second-price reward ==");
            println!("Shadow verification passed: Round 4");
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
            println!("Winner solver index: {}", winner_solver_index);
            println!("\n== Round 4 second-price reward ==");
            println!("Shadow verification passed: Round 4");
            if let Some(runner_up_solver_index) = runner_up_solver_index {
                println!("Runner-up solver index: {}", runner_up_solver_index);
            } else {
                println!("Runner-up solver index: none (single survivor branch)");
            }
            println!("Second price: {}", second_price);
            println!("Shadow verification passed: Settlement");
        }
    }
}

fn build_demo_solver_scores() -> Vec<SolverScoreTable> {
    let mut tables = synthetic_solver_score_tables(29);

    tables[0].scores = [420, 430, 410, 405, 415, 408, 412, 409];
    tables[1].scores = [420, 430, 410, 405, 415, 408, 412, 409];
    tables[2].scores = [420, 430, 410, 405, 415, 408, 412, 408];
    tables[3].scores = [300, 290, 295, 298, 301, 303, 304, 305];
    tables[4].scores = [310, 300, 299, 302, 306, 307, 308, 309];

    tables
}
