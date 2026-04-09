use auction_bitplane_example::{
    accumulate_bitplanes, build_eval_key, build_params, build_relin_key, encode_bid_into_planes,
    encode_bid_legacy, encrypt_bid_sk, encrypt_bitplanes_sk, find_winner_bitplane,
    find_winner_legacy, BID_BITS,
};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use fhe::bfv::SecretKey;
use rand::rngs::OsRng;
use rand::Rng;

fn bench_bitplane_find_winner(c: &mut Criterion) {
    let params = build_params();
    let mut rng = OsRng;
    let sk = SecretKey::random(&params, &mut rng);
    let eval_key = build_eval_key(&sk);
    let relin_key = build_relin_key(&sk);
    let bid_values: Vec<u64> = (0..10).map(|_| rng.gen()).collect();

    c.bench_function("bench_bitplane_find_winner", |b| {
        b.iter(|| {
            let mut global_bitplanes: Option<Vec<_>> = None;

            for (slot, value) in bid_values.iter().copied().enumerate() {
                let planes = encode_bid_into_planes(value, slot, &params);
                let contribution = encrypt_bitplanes_sk(&planes, &sk);

                if let Some(global) = global_bitplanes.as_mut() {
                    accumulate_bitplanes(global, &contribution);
                } else {
                    global_bitplanes = Some(contribution);
                }
            }

            let global_bitplanes = global_bitplanes.expect("expected benchmark bidders");
            debug_assert_eq!(global_bitplanes.len(), BID_BITS);

            let result = find_winner_bitplane(
                &global_bitplanes,
                bid_values.len(),
                &eval_key,
                &relin_key,
                &sk,
                &params,
            );
            black_box(result);
        })
    });
}

fn bench_legacy_find_winner(c: &mut Criterion) {
    let params = build_params();
    let mut rng = OsRng;
    let sk = SecretKey::random(&params, &mut rng);
    let eval_key = build_eval_key(&sk);
    let relin_key = build_relin_key(&sk);
    let bid_values: Vec<u64> = (0..10).map(|_| rng.gen()).collect();

    c.bench_function("bench_legacy_find_winner", |b| {
        b.iter(|| {
            let bids = bid_values
                .iter()
                .copied()
                .map(|value| {
                    let pt = encode_bid_legacy(value, &params);
                    encrypt_bid_sk(&pt, &sk)
                })
                .collect::<Vec<_>>();

            black_box(find_winner_legacy(
                &bids, &eval_key, &relin_key, &sk, &params,
            ));
        })
    });
}

criterion_group!(
    benches,
    bench_bitplane_find_winner,
    bench_legacy_find_winner
);
criterion_main!(benches);
