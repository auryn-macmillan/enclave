// SPDX-License-Identifier: LGPL-3.0-only

pub use auction_bitplane_example::{
    aggregate_public_key, aggregate_sk_shares_for_party, build_params, compute_decryption_shares,
    encrypt_bid, generate_crp, generate_smudging_noise, member_keygen, threshold_decrypt,
    MemberKeygenOutput, COMMITTEE_N,
};

use fhe::bfv::{BfvParameters, Ciphertext, Encoding, Plaintext, PublicKey};
use fhe_traits::{FheDecoder, FheEncoder};
use std::cmp::Ordering;
use std::sync::Arc;

pub const NUM_PAIRS: usize = 8;
pub const NUM_SOLVERS: usize = 15;
pub const MAX_SCORE: u64 = 6000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CombinatorialAuctionConfig {
    pub num_pairs: usize,
    pub num_solvers: usize,
    pub committee_size: usize,
}

impl Default for CombinatorialAuctionConfig {
    fn default() -> Self {
        Self {
            num_pairs: NUM_PAIRS,
            num_solvers: NUM_SOLVERS,
            committee_size: COMMITTEE_N,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TokenPair {
    pub base_token: u8,
    pub quote_token: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Direction {
    Forward,
    Reverse,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DirectedPair {
    pub pair_index: usize,
    pub token_pair: TokenPair,
    pub direction: Direction,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicUserIntent {
    pub user_id: usize,
    pub pair: DirectedPair,
    pub quantity: u64,
    pub limit_price: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StandaloneScoreTable {
    pub solver_id: usize,
    pub scores: [u64; NUM_PAIRS],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchedScoreTable {
    pub solver_id: usize,
    pub scores: [u64; NUM_PAIRS],
}

trait ScoreTableView {
    fn scores(&self) -> &[u64; NUM_PAIRS];
}

impl ScoreTableView for StandaloneScoreTable {
    fn scores(&self) -> &[u64; NUM_PAIRS] {
        &self.scores
    }
}

impl ScoreTableView for BatchedScoreTable {
    fn scores(&self) -> &[u64; NUM_PAIRS] {
        &self.scores
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Round1Comparison {
    pub pair_index: usize,
    pub incumbent_solver_index: usize,
    pub challenger_solver_index: usize,
    pub ordering: Ordering,
    pub winning_solver_index: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Round1ReferenceOutcome {
    pub winner_solver_indices: [usize; NUM_PAIRS],
    pub comparisons: Vec<Round1Comparison>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FairnessFilterResult {
    pub survivors: Vec<usize>,
    pub fallback_to_reference: bool,
    pub reference_outcome: Round1ReferenceOutcome,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuctionSettlement {
    ReferenceFallback {
        reference_outcome: Round1ReferenceOutcome,
    },
    BatchedWinner {
        winner_solver_index: usize,
        second_price: u64,
        runner_up_solver_index: Option<usize>,
        reference_outcome: Round1ReferenceOutcome,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FoundationError {
    InvalidScore {
        index: usize,
        score: u64,
    },
    WrongScoreCount {
        expected: usize,
        actual: usize,
    },
    WrongSolverCount {
        expected: usize,
        actual: usize,
    },
    SolverIdMismatch {
        index: usize,
        expected: usize,
        actual: usize,
    },
    NotEnoughSlots {
        expected: usize,
        actual: usize,
    },
    EncodeFailed,
    DecodeFailed,
    EmptySolvers,
    NotEnoughParties {
        required: usize,
        actual: usize,
    },
    InvalidPartyIndex {
        index: usize,
    },
    WrongCommitteeSize {
        expected: usize,
        actual: usize,
    },
}

pub fn build_config() -> CombinatorialAuctionConfig {
    CombinatorialAuctionConfig::default()
}

pub fn example_name() -> &'static str {
    "combinatorial-auction"
}

pub fn sign_of_difference(decrypted: u64, plaintext_modulus: u64) -> Ordering {
    assert!(plaintext_modulus > 1, "plaintext modulus must exceed one");
    assert!(plaintext_modulus % 2 == 1, "plaintext modulus must be odd");
    assert!(
        decrypted < plaintext_modulus,
        "decrypted value must be reduced modulo plaintext modulus"
    );

    if decrypted == 0 {
        Ordering::Equal
    } else if decrypted < plaintext_modulus / 2 {
        Ordering::Greater
    } else {
        Ordering::Less
    }
}

pub fn validate_score(score: u64) -> Result<u64, FoundationError> {
    if score <= MAX_SCORE {
        Ok(score)
    } else {
        Err(FoundationError::InvalidScore { index: 0, score })
    }
}

pub fn validate_solver_scores(scores: &[u64]) -> Result<(), FoundationError> {
    if scores.len() != NUM_PAIRS {
        return Err(FoundationError::WrongScoreCount {
            expected: NUM_PAIRS,
            actual: scores.len(),
        });
    }

    for (index, &score) in scores.iter().enumerate() {
        if score > MAX_SCORE {
            return Err(FoundationError::InvalidScore { index, score });
        }
    }

    Ok(())
}

pub fn encode_solver_scores(
    scores: &[u64],
    params: &Arc<BfvParameters>,
) -> Result<Plaintext, FoundationError> {
    validate_solver_scores(scores)?;
    if params.degree() < NUM_PAIRS {
        return Err(FoundationError::NotEnoughSlots {
            expected: NUM_PAIRS,
            actual: params.degree(),
        });
    }

    let mut slots = vec![0u64; params.degree()];
    slots[..NUM_PAIRS].copy_from_slice(scores);

    Plaintext::try_encode(&slots, Encoding::simd(), params)
        .map_err(|_| FoundationError::EncodeFailed)
}

pub fn decode_solver_scores(slots: &[u64]) -> Result<[u64; NUM_PAIRS], FoundationError> {
    if slots.len() < NUM_PAIRS {
        return Err(FoundationError::NotEnoughSlots {
            expected: NUM_PAIRS,
            actual: slots.len(),
        });
    }

    let mut scores = [0u64; NUM_PAIRS];
    for (index, score) in scores.iter_mut().enumerate() {
        *score = validate_score(slots[index]).map_err(|_| FoundationError::InvalidScore {
            index,
            score: slots[index],
        })?;
    }

    Ok(scores)
}

pub fn decode_solver_scores_plaintext(
    plaintext: &Plaintext,
) -> Result<[u64; NUM_PAIRS], FoundationError> {
    let slots = Vec::<u64>::try_decode(plaintext, Encoding::simd())
        .map_err(|_| FoundationError::DecodeFailed)?;
    decode_solver_scores(&slots)
}

pub fn encrypt_solver_scores(plaintext: &Plaintext, public_key: &PublicKey) -> Ciphertext {
    encrypt_bid(plaintext, public_key)
}

pub fn synthetic_directed_pairs() -> [DirectedPair; NUM_PAIRS] {
    let token_pairs = [
        TokenPair {
            base_token: 0,
            quote_token: 1,
        },
        TokenPair {
            base_token: 0,
            quote_token: 2,
        },
        TokenPair {
            base_token: 1,
            quote_token: 2,
        },
        TokenPair {
            base_token: 1,
            quote_token: 3,
        },
    ];

    let mut directed_pairs = [DirectedPair {
        pair_index: 0,
        token_pair: token_pairs[0],
        direction: Direction::Forward,
    }; NUM_PAIRS];

    for (pair_index, token_pair) in token_pairs.into_iter().enumerate() {
        directed_pairs[pair_index * 2] = DirectedPair {
            pair_index: pair_index * 2,
            token_pair,
            direction: Direction::Forward,
        };
        directed_pairs[pair_index * 2 + 1] = DirectedPair {
            pair_index: pair_index * 2 + 1,
            token_pair,
            direction: Direction::Reverse,
        };
    }

    directed_pairs
}

pub fn synthetic_public_intents(seed: u64, count: usize) -> Vec<PublicUserIntent> {
    let pairs = synthetic_directed_pairs();

    (0..count)
        .map(|user_id| {
            let entropy = mix(seed, user_id as u64 + 1);
            let pair = pairs[(entropy as usize) % NUM_PAIRS];
            let quantity = entropy % 25 + 1;
            let limit_price = 100 + ((entropy >> 8) % 900);

            PublicUserIntent {
                user_id,
                pair,
                quantity,
                limit_price,
            }
        })
        .collect()
}

fn synthetic_score_array(seed: u64, solver_id: usize, stream_tag: u64) -> [u64; NUM_PAIRS] {
    let mut scores = [0u64; NUM_PAIRS];
    for (pair_index, score) in scores.iter_mut().enumerate() {
        *score = mix(seed ^ stream_tag ^ solver_id as u64, pair_index as u64) % (MAX_SCORE + 1);
    }

    scores
}

pub fn synthetic_standalone_score_tables(seed: u64) -> Vec<StandaloneScoreTable> {
    (0..NUM_SOLVERS)
        .map(|solver_id| {
            let scores = synthetic_score_array(seed, solver_id, 0x5354_414e_4441_4c4f);

            StandaloneScoreTable { solver_id, scores }
        })
        .collect()
}

pub fn synthetic_batched_score_tables(seed: u64) -> Vec<BatchedScoreTable> {
    (0..NUM_SOLVERS)
        .map(|solver_id| {
            let scores = synthetic_score_array(seed, solver_id, 0x4241_5443_4845_4400);

            BatchedScoreTable { solver_id, scores }
        })
        .collect()
}

pub fn synthetic_solver_bid_tables(
    seed: u64,
) -> (Vec<StandaloneScoreTable>, Vec<BatchedScoreTable>) {
    (
        synthetic_standalone_score_tables(seed),
        synthetic_batched_score_tables(seed),
    )
}

fn validate_score_table<T: ScoreTableView>(table: &T) -> Result<(), FoundationError> {
    validate_solver_scores(table.scores())
}

fn validate_solver_bid_alignment(
    standalone_tables: &[StandaloneScoreTable],
    batched_tables: &[BatchedScoreTable],
) -> Result<(), FoundationError> {
    if standalone_tables.len() != batched_tables.len() {
        return Err(FoundationError::WrongSolverCount {
            expected: standalone_tables.len(),
            actual: batched_tables.len(),
        });
    }

    for (index, (standalone_table, batched_table)) in standalone_tables
        .iter()
        .zip(batched_tables.iter())
        .enumerate()
    {
        if standalone_table.solver_id != batched_table.solver_id {
            return Err(FoundationError::SolverIdMismatch {
                index,
                expected: standalone_table.solver_id,
                actual: batched_table.solver_id,
            });
        }

        validate_score_table(standalone_table)?;
        validate_score_table(batched_table)?;
    }

    Ok(())
}

fn validate_encrypted_bid_counts(
    standalone_scores: &[Ciphertext],
    batched_scores: &[Ciphertext],
) -> Result<(), FoundationError> {
    if standalone_scores.len() != batched_scores.len() {
        return Err(FoundationError::WrongSolverCount {
            expected: standalone_scores.len(),
            actual: batched_scores.len(),
        });
    }

    Ok(())
}

pub fn round1_reference_outcome_shadow(
    standalone_tables: &[StandaloneScoreTable],
) -> Result<Round1ReferenceOutcome, FoundationError> {
    if standalone_tables.is_empty() {
        return Err(FoundationError::EmptySolvers);
    }

    for table in standalone_tables {
        validate_score_table(table)?;
    }

    let mut winner_solver_indices = [0usize; NUM_PAIRS];
    let mut comparisons = Vec::with_capacity(NUM_PAIRS * standalone_tables.len().saturating_sub(1));

    for (pair_index, winner_solver_index) in winner_solver_indices.iter_mut().enumerate() {
        let mut incumbent_solver_index = 0usize;
        let mut incumbent_score = standalone_tables[0].scores[pair_index];

        for (challenger_solver_index, challenger_table) in
            standalone_tables.iter().enumerate().skip(1)
        {
            let prior_incumbent_solver_index = incumbent_solver_index;
            let challenger_score = challenger_table.scores[pair_index];
            let ordering = challenger_score.cmp(&incumbent_score);
            if ordering == Ordering::Greater {
                incumbent_solver_index = challenger_solver_index;
                incumbent_score = challenger_score;
            }

            comparisons.push(Round1Comparison {
                pair_index,
                incumbent_solver_index: prior_incumbent_solver_index,
                challenger_solver_index,
                ordering,
                winning_solver_index: incumbent_solver_index,
            });
        }

        *winner_solver_index = incumbent_solver_index;
    }

    Ok(Round1ReferenceOutcome {
        winner_solver_indices,
        comparisons,
    })
}

pub fn round1_reference_outcome_fhe(
    encrypted_scores: &[Ciphertext],
    committee_members: &[MemberKeygenOutput],
    participating_parties: &[usize],
    params: &Arc<BfvParameters>,
) -> Result<Round1ReferenceOutcome, FoundationError> {
    if encrypted_scores.is_empty() {
        return Err(FoundationError::EmptySolvers);
    }
    if committee_members.len() != COMMITTEE_N {
        return Err(FoundationError::WrongCommitteeSize {
            expected: COMMITTEE_N,
            actual: committee_members.len(),
        });
    }
    if participating_parties.len() < 2 {
        return Err(FoundationError::NotEnoughParties {
            required: 2,
            actual: participating_parties.len(),
        });
    }
    for &party_index in participating_parties {
        if party_index >= committee_members.len() {
            return Err(FoundationError::InvalidPartyIndex { index: party_index });
        }
    }

    let all_member_shares = committee_members
        .iter()
        .map(|member| member.sk_shares.clone())
        .collect::<Vec<_>>();
    let sk_poly_sums = (0..committee_members.len())
        .map(|party_idx| aggregate_sk_shares_for_party(&all_member_shares, party_idx, params))
        .collect::<Vec<_>>();

    let mut winner_solver_indices = [0usize; NUM_PAIRS];
    let mut comparisons = Vec::with_capacity(NUM_PAIRS * encrypted_scores.len().saturating_sub(1));

    for (pair_index, winner_solver_index) in winner_solver_indices.iter_mut().enumerate() {
        let mut incumbent_solver_index = 0usize;

        for challenger_solver_index in 1..encrypted_scores.len() {
            let prior_incumbent_solver_index = incumbent_solver_index;
            let difference = &encrypted_scores[challenger_solver_index]
                - &encrypted_scores[prior_incumbent_solver_index];

            let party_shares: Vec<(usize, Vec<_>)> = participating_parties
                .iter()
                .map(|&party_idx| {
                    let smudging = generate_smudging_noise(params, 1);
                    let shares = compute_decryption_shares(
                        std::slice::from_ref(&difference),
                        &sk_poly_sums[party_idx],
                        &smudging,
                        params,
                    );
                    (party_idx + 1, shares)
                })
                .collect();

            let plaintexts =
                threshold_decrypt(&party_shares, std::slice::from_ref(&difference), params);
            let difference_slots = Vec::<u64>::try_decode(&plaintexts[0], Encoding::simd())
                .map_err(|_| FoundationError::DecodeFailed)?;
            let ordering = sign_of_difference(difference_slots[pair_index], params.plaintext());

            if ordering == Ordering::Greater {
                incumbent_solver_index = challenger_solver_index;
            }

            comparisons.push(Round1Comparison {
                pair_index,
                incumbent_solver_index: prior_incumbent_solver_index,
                challenger_solver_index,
                ordering,
                winning_solver_index: incumbent_solver_index,
            });
        }

        *winner_solver_index = incumbent_solver_index;
    }

    Ok(Round1ReferenceOutcome {
        winner_solver_indices,
        comparisons,
    })
}

pub fn round2_fairness_filter_shadow(
    standalone_tables: &[StandaloneScoreTable],
    batched_tables: &[BatchedScoreTable],
) -> Result<FairnessFilterResult, FoundationError> {
    validate_solver_bid_alignment(standalone_tables, batched_tables)?;

    let reference_outcome = round1_reference_outcome_shadow(standalone_tables)?;

    let mut survivors = Vec::new();
    for (solver_index, solver_table) in batched_tables.iter().enumerate() {
        let mut survives = true;

        for pair_index in 0..NUM_PAIRS {
            let reference_solver_index = reference_outcome.winner_solver_indices[pair_index];
            let reference_score = standalone_tables[reference_solver_index].scores[pair_index];
            if solver_table.scores[pair_index] < reference_score {
                survives = false;
                break;
            }
        }

        if survives {
            survivors.push(solver_index);
        }
    }

    let fallback_to_reference = survivors.is_empty();

    Ok(FairnessFilterResult {
        survivors,
        fallback_to_reference,
        reference_outcome,
    })
}

pub fn round2_fairness_filter_fhe(
    encrypted_standalone_scores: &[Ciphertext],
    encrypted_batched_scores: &[Ciphertext],
    committee_members: &[MemberKeygenOutput],
    participating_parties: &[usize],
    params: &Arc<BfvParameters>,
) -> Result<FairnessFilterResult, FoundationError> {
    validate_encrypted_bid_counts(encrypted_standalone_scores, encrypted_batched_scores)?;

    let reference_outcome = round1_reference_outcome_fhe(
        encrypted_standalone_scores,
        committee_members,
        participating_parties,
        params,
    )?;

    let all_member_shares = committee_members
        .iter()
        .map(|member| member.sk_shares.clone())
        .collect::<Vec<_>>();
    let sk_poly_sums = (0..committee_members.len())
        .map(|party_idx| aggregate_sk_shares_for_party(&all_member_shares, party_idx, params))
        .collect::<Vec<_>>();

    let mut survivors = Vec::new();
    for (solver_index, batched_ciphertext) in encrypted_batched_scores.iter().enumerate() {
        let mut survives = true;

        for pair_index in 0..NUM_PAIRS {
            let reference_solver_index = reference_outcome.winner_solver_indices[pair_index];
            let difference =
                batched_ciphertext - &encrypted_standalone_scores[reference_solver_index];

            let party_shares: Vec<(usize, Vec<_>)> = participating_parties
                .iter()
                .map(|&party_idx| {
                    let smudging = generate_smudging_noise(params, 1);
                    let shares = compute_decryption_shares(
                        std::slice::from_ref(&difference),
                        &sk_poly_sums[party_idx],
                        &smudging,
                        params,
                    );
                    (party_idx + 1, shares)
                })
                .collect();

            let plaintexts =
                threshold_decrypt(&party_shares, std::slice::from_ref(&difference), params);
            let difference_slots = Vec::<u64>::try_decode(&plaintexts[0], Encoding::simd())
                .map_err(|_| FoundationError::DecodeFailed)?;

            if sign_of_difference(difference_slots[pair_index], params.plaintext())
                == Ordering::Less
            {
                survives = false;
                break;
            }
        }

        if survives {
            survivors.push(solver_index);
        }
    }

    let fallback_to_reference = survivors.is_empty();

    Ok(FairnessFilterResult {
        survivors,
        fallback_to_reference,
        reference_outcome,
    })
}

pub fn total_score(scores: &[u64; NUM_PAIRS]) -> u64 {
    scores.iter().sum()
}

pub fn reference_total_score_shadow(
    standalone_tables: &[StandaloneScoreTable],
    reference_outcome: &Round1ReferenceOutcome,
) -> u64 {
    (0..NUM_PAIRS)
        .map(|pair_index| {
            let solver_index = reference_outcome.winner_solver_indices[pair_index];
            standalone_tables[solver_index].scores[pair_index]
        })
        .sum()
}

pub fn settle_auction_shadow(
    standalone_tables: &[StandaloneScoreTable],
    batched_tables: &[BatchedScoreTable],
) -> Result<AuctionSettlement, FoundationError> {
    let fairness = round2_fairness_filter_shadow(standalone_tables, batched_tables)?;

    if fairness.fallback_to_reference {
        return Ok(AuctionSettlement::ReferenceFallback {
            reference_outcome: fairness.reference_outcome,
        });
    }

    let survivor_totals: Vec<(usize, u64)> = fairness
        .survivors
        .iter()
        .map(|&solver_index| {
            (
                solver_index,
                total_score(&batched_tables[solver_index].scores),
            )
        })
        .collect();

    if survivor_totals.len() == 1 {
        return Ok(AuctionSettlement::BatchedWinner {
            winner_solver_index: survivor_totals[0].0,
            second_price: reference_total_score_shadow(
                standalone_tables,
                &fairness.reference_outcome,
            ),
            runner_up_solver_index: None,
            reference_outcome: fairness.reference_outcome,
        });
    }

    let (winner_solver_index, _) = best_total_entry(&survivor_totals).expect("non-empty survivors");
    let runner_up_candidates = survivor_totals
        .iter()
        .copied()
        .filter(|(solver_index, _)| *solver_index != winner_solver_index)
        .collect::<Vec<_>>();
    let (runner_up_solver_index, second_price) =
        best_total_entry(&runner_up_candidates).expect("multi-survivor runner-up");

    Ok(AuctionSettlement::BatchedWinner {
        winner_solver_index,
        second_price,
        runner_up_solver_index: Some(runner_up_solver_index),
        reference_outcome: fairness.reference_outcome,
    })
}

pub fn settle_auction_fhe(
    encrypted_standalone_scores: &[Ciphertext],
    encrypted_batched_scores: &[Ciphertext],
    committee_members: &[MemberKeygenOutput],
    participating_parties: &[usize],
    params: &Arc<BfvParameters>,
) -> Result<AuctionSettlement, FoundationError> {
    let fairness = round2_fairness_filter_fhe(
        encrypted_standalone_scores,
        encrypted_batched_scores,
        committee_members,
        participating_parties,
        params,
    )?;

    if fairness.fallback_to_reference {
        return Ok(AuctionSettlement::ReferenceFallback {
            reference_outcome: fairness.reference_outcome,
        });
    }

    let all_member_shares = committee_members
        .iter()
        .map(|member| member.sk_shares.clone())
        .collect::<Vec<_>>();
    let sk_poly_sums = (0..committee_members.len())
        .map(|party_idx| aggregate_sk_shares_for_party(&all_member_shares, party_idx, params))
        .collect::<Vec<_>>();

    let decrypt_slots = |ciphertext: &Ciphertext| -> Result<Vec<u64>, FoundationError> {
        let party_shares: Vec<(usize, Vec<_>)> = participating_parties
            .iter()
            .map(|&party_idx| {
                let smudging = generate_smudging_noise(params, 1);
                let shares = compute_decryption_shares(
                    std::slice::from_ref(ciphertext),
                    &sk_poly_sums[party_idx],
                    &smudging,
                    params,
                );
                (party_idx + 1, shares)
            })
            .collect();

        let plaintexts = threshold_decrypt(&party_shares, std::slice::from_ref(ciphertext), params);
        Vec::<u64>::try_decode(&plaintexts[0], Encoding::simd())
            .map_err(|_| FoundationError::DecodeFailed)
    };

    if fairness.survivors.len() == 1 {
        let mut reference_total = 0u64;
        for pair_index in 0..NUM_PAIRS {
            let solver_index = fairness.reference_outcome.winner_solver_indices[pair_index];
            let slots = decrypt_slots(&encrypted_standalone_scores[solver_index])?;
            reference_total += slots[pair_index];
        }

        return Ok(AuctionSettlement::BatchedWinner {
            winner_solver_index: fairness.survivors[0],
            second_price: reference_total,
            runner_up_solver_index: None,
            reference_outcome: fairness.reference_outcome,
        });
    }

    let mut winner_solver_index = fairness.survivors[0];
    for &challenger_solver_index in fairness.survivors.iter().skip(1) {
        let difference = &encrypted_batched_scores[challenger_solver_index]
            - &encrypted_batched_scores[winner_solver_index];
        let slots = decrypt_slots(&difference)?;
        let total_difference = sum_centered_difference_slots(&slots, params.plaintext());

        if total_difference > 0 {
            winner_solver_index = challenger_solver_index;
        }
    }

    let mut runner_up_solver_index = fairness
        .survivors
        .iter()
        .copied()
        .find(|&solver_index| solver_index != winner_solver_index)
        .expect("multi-survivor runner-up seed");

    for &challenger_solver_index in fairness.survivors.iter().skip(1) {
        if challenger_solver_index == winner_solver_index
            || challenger_solver_index == runner_up_solver_index
        {
            continue;
        }

        let difference = &encrypted_batched_scores[challenger_solver_index]
            - &encrypted_batched_scores[runner_up_solver_index];
        let slots = decrypt_slots(&difference)?;
        let total_difference = sum_centered_difference_slots(&slots, params.plaintext());

        if total_difference > 0 {
            runner_up_solver_index = challenger_solver_index;
        }
    }

    let runner_up_slots = decrypt_slots(&encrypted_batched_scores[runner_up_solver_index])?;
    let second_price = sum_score_slots(&runner_up_slots);

    Ok(AuctionSettlement::BatchedWinner {
        winner_solver_index,
        second_price,
        runner_up_solver_index: Some(runner_up_solver_index),
        reference_outcome: fairness.reference_outcome,
    })
}

fn best_total_entry(entries: &[(usize, u64)]) -> Option<(usize, u64)> {
    let mut best = entries.first().copied()?;
    for &(solver_index, total) in entries.iter().skip(1) {
        if total > best.1 {
            best = (solver_index, total);
        }
    }
    Some(best)
}

fn sum_score_slots(slots: &[u64]) -> u64 {
    slots.iter().take(NUM_PAIRS).sum()
}

fn centered_difference(raw: u64, plaintext_modulus: u64) -> i64 {
    match sign_of_difference(raw, plaintext_modulus) {
        Ordering::Equal => 0,
        Ordering::Greater => raw as i64,
        Ordering::Less => raw as i64 - plaintext_modulus as i64,
    }
}

fn sum_centered_difference_slots(slots: &[u64], plaintext_modulus: u64) -> i64 {
    slots
        .iter()
        .take(NUM_PAIRS)
        .map(|&slot| centered_difference(slot, plaintext_modulus))
        .sum()
}

fn mix(seed: u64, stream: u64) -> u64 {
    let mut value = seed ^ stream.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    value ^= value >> 30;
    value = value.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94D0_49BB_1331_11EB);
    value ^ (value >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::slice;

    fn sample_scores() -> [u64; NUM_PAIRS] {
        [0, 1, 17, 255, 1024, 4096, 5999, 6000]
    }

    fn scores_with_prefix(prefix: &[(usize, u64)]) -> [u64; NUM_PAIRS] {
        let mut scores = [0u64; NUM_PAIRS];
        for &(pair_index, score) in prefix {
            scores[pair_index] = score;
        }
        scores
    }

    fn sample_round1_standalone_tables() -> Vec<StandaloneScoreTable> {
        vec![
            StandaloneScoreTable {
                solver_id: 0,
                scores: scores_with_prefix(&[
                    (0, 100),
                    (1, 80),
                    (2, 90),
                    (3, 60),
                    (4, 55),
                    (5, 10),
                    (6, 6000),
                    (7, 100),
                ]),
            },
            StandaloneScoreTable {
                solver_id: 1,
                scores: scores_with_prefix(&[
                    (0, 120),
                    (1, 70),
                    (2, 90),
                    (3, 61),
                    (4, 55),
                    (5, 6000),
                    (6, 5999),
                    (7, 100),
                ]),
            },
            StandaloneScoreTable {
                solver_id: 2,
                scores: scores_with_prefix(&[
                    (0, 119),
                    (1, 81),
                    (2, 90),
                    (3, 59),
                    (4, 6000),
                    (5, 200),
                    (6, 100),
                    (7, 100),
                ]),
            },
        ]
    }

    fn sample_round2_some_survive_tables() -> (Vec<StandaloneScoreTable>, Vec<BatchedScoreTable>) {
        (
            vec![
                StandaloneScoreTable {
                    solver_id: 0,
                    scores: [100, 200, 300, 400, 500, 600, 700, 800],
                },
                StandaloneScoreTable {
                    solver_id: 1,
                    scores: [90, 190, 280, 390, 490, 590, 690, 790],
                },
                StandaloneScoreTable {
                    solver_id: 2,
                    scores: [80, 180, 270, 380, 480, 580, 680, 780],
                },
            ],
            vec![
                BatchedScoreTable {
                    solver_id: 0,
                    scores: [100, 200, 300, 400, 500, 600, 700, 800],
                },
                BatchedScoreTable {
                    solver_id: 1,
                    scores: [100, 200, 300, 400, 500, 600, 700, 800],
                },
                BatchedScoreTable {
                    solver_id: 2,
                    scores: [100, 200, 299, 400, 500, 600, 700, 800],
                },
            ],
        )
    }

    fn sample_round2_all_survive_tables() -> (Vec<StandaloneScoreTable>, Vec<BatchedScoreTable>) {
        (
            vec![
                StandaloneScoreTable {
                    solver_id: 0,
                    scores: [777; NUM_PAIRS],
                },
                StandaloneScoreTable {
                    solver_id: 1,
                    scores: [777; NUM_PAIRS],
                },
                StandaloneScoreTable {
                    solver_id: 2,
                    scores: [777; NUM_PAIRS],
                },
            ],
            vec![
                BatchedScoreTable {
                    solver_id: 0,
                    scores: [777; NUM_PAIRS],
                },
                BatchedScoreTable {
                    solver_id: 1,
                    scores: [777; NUM_PAIRS],
                },
                BatchedScoreTable {
                    solver_id: 2,
                    scores: [777; NUM_PAIRS],
                },
            ],
        )
    }

    fn sample_round3_single_survivor_tables() -> (Vec<StandaloneScoreTable>, Vec<BatchedScoreTable>)
    {
        (
            vec![
                StandaloneScoreTable {
                    solver_id: 0,
                    scores: [500; NUM_PAIRS],
                },
                StandaloneScoreTable {
                    solver_id: 1,
                    scores: [500, 500, 500, 500, 500, 500, 500, 499],
                },
                StandaloneScoreTable {
                    solver_id: 2,
                    scores: [400; NUM_PAIRS],
                },
            ],
            vec![
                BatchedScoreTable {
                    solver_id: 0,
                    scores: [500; NUM_PAIRS],
                },
                BatchedScoreTable {
                    solver_id: 1,
                    scores: [500, 500, 500, 500, 500, 500, 500, 499],
                },
                BatchedScoreTable {
                    solver_id: 2,
                    scores: [400; NUM_PAIRS],
                },
            ],
        )
    }

    fn sample_batched_beats_reference_tables() -> (Vec<StandaloneScoreTable>, Vec<BatchedScoreTable>)
    {
        (
            vec![
                StandaloneScoreTable {
                    solver_id: 0,
                    scores: [100, 180, 130, 160, 120, 170, 140, 150],
                },
                StandaloneScoreTable {
                    solver_id: 1,
                    scores: [150, 120, 180, 130, 170, 110, 190, 100],
                },
                StandaloneScoreTable {
                    solver_id: 2,
                    scores: [130, 170, 120, 190, 110, 180, 100, 200],
                },
            ],
            vec![
                BatchedScoreTable {
                    solver_id: 0,
                    scores: [155, 185, 182, 195, 172, 184, 193, 205],
                },
                BatchedScoreTable {
                    solver_id: 1,
                    scores: [150, 180, 180, 190, 170, 180, 190, 201],
                },
                BatchedScoreTable {
                    solver_id: 2,
                    scores: [149, 180, 180, 190, 170, 180, 190, 205],
                },
            ],
        )
    }

    fn encrypt_score_tables<T: ScoreTableView>(
        score_tables: &[T],
        params: &Arc<BfvParameters>,
        public_key: &PublicKey,
    ) -> Vec<Ciphertext> {
        score_tables
            .iter()
            .map(|table| {
                let plaintext =
                    encode_solver_scores(table.scores(), params).expect("encode scores");
                encrypt_solver_scores(&plaintext, public_key)
            })
            .collect()
    }

    fn setup_committee() -> (Arc<BfvParameters>, Vec<MemberKeygenOutput>, PublicKey) {
        let params = build_params();
        let crp = generate_crp(&params);
        let members = (0..COMMITTEE_N)
            .map(|_| member_keygen(&params, &crp))
            .collect::<Vec<_>>();
        let public_key = aggregate_public_key(
            members
                .iter()
                .map(|member| member.pk_share.clone())
                .collect(),
        );

        (params, members, public_key)
    }

    #[test]
    fn test_sign_of_difference_boundaries() {
        let t = 12289;

        assert_eq!(sign_of_difference(0, t), Ordering::Equal);
        assert_eq!(sign_of_difference(1, t), Ordering::Greater);
        assert_eq!(sign_of_difference(6000, t), Ordering::Greater);
        assert_eq!(sign_of_difference(6143, t), Ordering::Greater);
        assert_eq!(sign_of_difference(6144, t), Ordering::Less);
        assert_eq!(sign_of_difference(12288, t), Ordering::Less);
    }

    #[test]
    fn test_encode_decode_solver_scores_roundtrip() {
        let params = build_params();
        let scores = sample_scores();
        let plaintext = encode_solver_scores(&scores, &params).expect("encode scores");
        let slots = Vec::<u64>::try_decode(&plaintext, Encoding::simd()).expect("decode slots");

        assert_eq!(decode_solver_scores(&slots).expect("decode scores"), scores);
        assert!(slots[NUM_PAIRS..].iter().all(|&slot| slot == 0));
    }

    #[test]
    fn test_encrypt_decrypt_solver_scores_roundtrip() {
        let params = build_params();
        let crp = generate_crp(&params);
        let members = (0..COMMITTEE_N)
            .map(|_| member_keygen(&params, &crp))
            .collect::<Vec<_>>();

        let public_key = aggregate_public_key(
            members
                .iter()
                .map(|member| member.pk_share.clone())
                .collect(),
        );
        let all_member_shares = members
            .iter()
            .map(|member| member.sk_shares.clone())
            .collect::<Vec<_>>();
        let sk_poly_sums = (0..COMMITTEE_N)
            .map(|party_idx| aggregate_sk_shares_for_party(&all_member_shares, party_idx, &params))
            .collect::<Vec<_>>();

        let scores = sample_scores();
        let plaintext = encode_solver_scores(&scores, &params).expect("encode scores");
        let ciphertext = encrypt_solver_scores(&plaintext, &public_key);

        let party_shares: Vec<(usize, Vec<_>)> = [0usize, 1usize]
            .into_iter()
            .map(|party_idx| {
                let smudging = generate_smudging_noise(&params, 1);
                let shares = compute_decryption_shares(
                    slice::from_ref(&ciphertext),
                    &sk_poly_sums[party_idx],
                    &smudging,
                    &params,
                );
                (party_idx + 1, shares)
            })
            .collect();

        let decrypted = threshold_decrypt(&party_shares, slice::from_ref(&ciphertext), &params);
        let roundtrip = decode_solver_scores_plaintext(&decrypted[0]).expect("decode plaintext");

        assert_eq!(roundtrip, scores);
    }

    #[test]
    fn test_invalid_score_rejection() {
        let params = build_params();
        let mut scores = sample_scores();
        scores[3] = MAX_SCORE + 1;

        assert_eq!(
            validate_solver_scores(&scores),
            Err(FoundationError::InvalidScore {
                index: 3,
                score: MAX_SCORE + 1,
            })
        );
        assert_eq!(
            encode_solver_scores(&scores, &params),
            Err(FoundationError::InvalidScore {
                index: 3,
                score: MAX_SCORE + 1,
            })
        );
    }

    #[test]
    fn test_synthetic_solver_scores_stay_in_range() {
        let (standalone_tables, batched_tables) = synthetic_solver_bid_tables(7);

        assert_eq!(standalone_tables.len(), NUM_SOLVERS);
        assert_eq!(batched_tables.len(), NUM_SOLVERS);
        for table in standalone_tables {
            assert!(validate_solver_scores(&table.scores).is_ok());
        }
        for table in batched_tables {
            assert!(validate_solver_scores(&table.scores).is_ok());
        }
    }

    #[test]
    fn test_round1_shadow_known_reference_outcome() {
        let tables = sample_round1_standalone_tables();
        let outcome = round1_reference_outcome_shadow(&tables).expect("round1 shadow");

        assert_eq!(outcome.winner_solver_indices, [1, 2, 0, 1, 2, 1, 0, 0]);
        assert_eq!(outcome.comparisons.len(), NUM_PAIRS * 2);
    }

    #[test]
    fn test_round1_shadow_tie_breaks_to_lower_solver_index() {
        let tables = vec![
            StandaloneScoreTable {
                solver_id: 0,
                scores: [500; NUM_PAIRS],
            },
            StandaloneScoreTable {
                solver_id: 1,
                scores: [500; NUM_PAIRS],
            },
            StandaloneScoreTable {
                solver_id: 2,
                scores: [499; NUM_PAIRS],
            },
        ];

        let outcome = round1_reference_outcome_shadow(&tables).expect("round1 shadow");

        assert_eq!(outcome.winner_solver_indices, [0; NUM_PAIRS]);
        assert!(outcome
            .comparisons
            .iter()
            .all(|comparison| comparison.winning_solver_index == 0));
    }

    #[test]
    fn test_round1_shadow_single_solver_case() {
        let tables = vec![StandaloneScoreTable {
            solver_id: 0,
            scores: sample_scores(),
        }];

        let outcome = round1_reference_outcome_shadow(&tables).expect("round1 shadow");

        assert_eq!(outcome.winner_solver_indices, [0; NUM_PAIRS]);
        assert!(outcome.comparisons.is_empty());
    }

    #[test]
    fn test_round1_fhe_matches_plaintext_shadow() {
        let tables = sample_round1_standalone_tables();
        let shadow = round1_reference_outcome_shadow(&tables).expect("round1 shadow");
        let (params, members, public_key) = setup_committee();
        let encrypted_tables = encrypt_score_tables(&tables, &params, &public_key);

        let fhe_outcome =
            round1_reference_outcome_fhe(&encrypted_tables, &members, &[0, 1], &params)
                .expect("round1 fhe");

        assert_eq!(fhe_outcome, shadow);
    }

    #[test]
    fn test_round2_shadow_some_survive_some_fail() {
        let (standalone_tables, batched_tables) = sample_round2_some_survive_tables();

        let result = round2_fairness_filter_shadow(&standalone_tables, &batched_tables)
            .expect("round2 shadow");

        assert_eq!(result.survivors, vec![0, 1]);
        assert!(!result.fallback_to_reference);
        assert_eq!(
            result.reference_outcome.winner_solver_indices,
            [0; NUM_PAIRS]
        );
    }

    #[test]
    fn test_round2_shadow_all_survive() {
        let (standalone_tables, batched_tables) = sample_round2_all_survive_tables();

        let result = round2_fairness_filter_shadow(&standalone_tables, &batched_tables)
            .expect("round2 shadow");

        assert_eq!(result.survivors, vec![0, 1, 2]);
        assert!(!result.fallback_to_reference);
        assert_eq!(
            result.reference_outcome.winner_solver_indices,
            [0; NUM_PAIRS]
        );
    }

    #[test]
    fn test_round2_shadow_empty_survivor_fallback() {
        let standalone_tables = sample_round1_standalone_tables();
        let batched_tables = standalone_tables
            .iter()
            .map(|table| BatchedScoreTable {
                solver_id: table.solver_id,
                scores: table.scores,
            })
            .collect::<Vec<_>>();

        let result = round2_fairness_filter_shadow(&standalone_tables, &batched_tables)
            .expect("round2 shadow");

        assert!(result.survivors.is_empty());
        assert!(result.fallback_to_reference);
        assert_eq!(
            result.reference_outcome.winner_solver_indices,
            [1, 2, 0, 1, 2, 1, 0, 0]
        );
    }

    #[test]
    fn test_round2_fhe_matches_plaintext_shadow() {
        let (standalone_tables, batched_tables) = sample_round2_some_survive_tables();
        let shadow = round2_fairness_filter_shadow(&standalone_tables, &batched_tables)
            .expect("round2 shadow");
        let (params, members, public_key) = setup_committee();
        let encrypted_standalone_tables =
            encrypt_score_tables(&standalone_tables, &params, &public_key);
        let encrypted_batched_tables = encrypt_score_tables(&batched_tables, &params, &public_key);

        let fhe_result = round2_fairness_filter_fhe(
            &encrypted_standalone_tables,
            &encrypted_batched_tables,
            &members,
            &[0, 1],
            &params,
        )
        .expect("round2 fhe");

        assert_eq!(fhe_result, shadow);
    }

    #[test]
    fn test_settle_auction_shadow_multi_survivor_known_winner_runner_up() {
        let (standalone_tables, batched_tables) = sample_round2_all_survive_tables();

        let settlement =
            settle_auction_shadow(&standalone_tables, &batched_tables).expect("settlement shadow");

        assert_eq!(
            settlement,
            AuctionSettlement::BatchedWinner {
                winner_solver_index: 0,
                second_price: 6216,
                runner_up_solver_index: Some(1),
                reference_outcome: round1_reference_outcome_shadow(&standalone_tables)
                    .expect("reference"),
            }
        );
    }

    #[test]
    fn test_settle_auction_shadow_single_survivor_case() {
        let (standalone_tables, batched_tables) = sample_round3_single_survivor_tables();

        let settlement =
            settle_auction_shadow(&standalone_tables, &batched_tables).expect("settlement shadow");

        assert_eq!(
            settlement,
            AuctionSettlement::BatchedWinner {
                winner_solver_index: 0,
                second_price: 4000,
                runner_up_solver_index: None,
                reference_outcome: round1_reference_outcome_shadow(&standalone_tables)
                    .expect("reference"),
            }
        );
    }

    #[test]
    fn test_settle_auction_shadow_batched_winner_beats_reference_baseline() {
        let (standalone_tables, batched_tables) = sample_batched_beats_reference_tables();

        let reference_outcome =
            round1_reference_outcome_shadow(&standalone_tables).expect("reference");
        let reference_total = reference_total_score_shadow(&standalone_tables, &reference_outcome);
        let settlement =
            settle_auction_shadow(&standalone_tables, &batched_tables).expect("settlement shadow");

        assert_eq!(
            reference_outcome.winner_solver_indices,
            [1, 0, 1, 2, 1, 2, 1, 2]
        );
        assert_eq!(reference_total, 1440);
        assert_eq!(total_score(&batched_tables[0].scores), 1471);
        assert_eq!(
            settlement,
            AuctionSettlement::BatchedWinner {
                winner_solver_index: 0,
                second_price: 1441,
                runner_up_solver_index: Some(1),
                reference_outcome,
            }
        );
    }

    #[test]
    fn test_settle_auction_shadow_empty_survivor_fallback() {
        let standalone_tables = sample_round1_standalone_tables();
        let batched_tables = standalone_tables
            .iter()
            .map(|table| BatchedScoreTable {
                solver_id: table.solver_id,
                scores: table.scores,
            })
            .collect::<Vec<_>>();

        let settlement =
            settle_auction_shadow(&standalone_tables, &batched_tables).expect("settlement shadow");

        assert_eq!(
            settlement,
            AuctionSettlement::ReferenceFallback {
                reference_outcome: round1_reference_outcome_shadow(&standalone_tables)
                    .expect("reference"),
            }
        );
    }

    #[test]
    fn test_settle_auction_fhe_matches_shadow() {
        let (standalone_tables, batched_tables) = sample_batched_beats_reference_tables();
        let shadow =
            settle_auction_shadow(&standalone_tables, &batched_tables).expect("settlement shadow");
        let (params, members, public_key) = setup_committee();
        let encrypted_standalone_tables =
            encrypt_score_tables(&standalone_tables, &params, &public_key);
        let encrypted_batched_tables = encrypt_score_tables(&batched_tables, &params, &public_key);

        let fhe_settlement = settle_auction_fhe(
            &encrypted_standalone_tables,
            &encrypted_batched_tables,
            &members,
            &[0, 1],
            &params,
        )
        .expect("settlement fhe");

        assert_eq!(fhe_settlement, shadow);
    }
}
