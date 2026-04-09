use auction_bitplane_example::{
    BID_BITS, accumulate_bitplanes, build_eval_key, build_params, build_relin_key,
    compute_tallies, decrypt_tally_matrix, encode_bid_into_planes, encrypt_bitplanes_sk,
    find_winner_bitplane, rank_bidders_from_tallies,
};
use fhe::bfv::{Ciphertext, SecretKey};
use rand::rngs::OsRng;

#[actix_web::test]
async fn test_bitplane_logic_directly() {
    let params = build_params();
    let mut rng = OsRng;
    let sk: SecretKey = SecretKey::random(&params, &mut rng);
    let eval_key = build_eval_key(&sk);
    let relin_key = build_relin_key(&sk);

    let bid_values = [10u64, 20u64, 15u64];
    let mut global_bitplanes: Option<Vec<Ciphertext>> = None;

    for (slot, value) in bid_values.iter().copied().enumerate() {
        let planes = encode_bid_into_planes(value, slot, &params);
        let contribution = encrypt_bitplanes_sk(&planes, &sk);

        if let Some(global) = global_bitplanes.as_mut() {
            accumulate_bitplanes(global, &contribution);
        } else {
            global_bitplanes = Some(contribution);
        }
    }

    let global_bitplanes = global_bitplanes.expect("expected test bidders");
    assert_eq!(global_bitplanes.len(), BID_BITS);

    let tally_cts = compute_tallies(
        &global_bitplanes,
        bid_values.len(),
        &eval_key,
        &relin_key,
        &params,
    );
    let tally_matrix = decrypt_tally_matrix(&tally_cts, bid_values.len(), &sk, &params);
    let (winner_slot, second_slot) = rank_bidders_from_tallies(&tally_matrix);

    assert_eq!(winner_slot, 1);
    assert_eq!(second_slot, Some(2));
    assert_eq!(find_winner_bitplane(
        &global_bitplanes,
        bid_values.len(),
        &eval_key,
        &relin_key,
        &sk,
        &params,
    ), (1, Some(2)));
}
