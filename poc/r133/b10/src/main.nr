// SPDX-License-Identifier: LGPL-3.0-only
//
// r133 b10 — LIVENESS DISSOLVER for the 40,618/255-ACIR floor class (r133):
// 30-cell node grid where (a) each cell gets a DISTINCT pub domain-separator
// (cell-c 64-byte window of a pub salts matrix, gathered per byte with the
// pinned noir IF-comparator idiom) and (b) every node feeds a weighted
// accumulator pinned at the end (a real downstream consumer, not a top-level
// self-pin). Hypothesis under test: IF the floor is an identical-body
// optimization artifact -> this arm RESOLVES all 30 sponges (~30 x 40,618 g,
// ACIR ~30 x 255). IF it STILL lands on the 40,618/255 floor, the saturation
// is a measurement-layer property of the noir-beta.26/bb-5.1.0 path, not node
// data liveness.
use lib::math::commitments::compute_commitment;

fn main(
    sk_leaves: pub [Field; 30],
    esm_leaves: pub [Field; 30],
    salts: pub [u8; 1920],
    weights: pub [Field; 30],
    expected_acc: pub Field,
) {
    let mut acc: Field = 0;
    for c in 0..30 {
        let mut ds64: [u8; 64] = [0; 64];
        for k in 0..64 {
            let target: u32 = (c * 64 + k) as u32;
            if target < 1920 {
                ds64[k] = salts[target];
            }
        }
        let node = compute_commitment([sk_leaves[c], esm_leaves[c]], ds64);
        acc = acc + node * weights[c];
    }
    assert(acc == expected_acc, "acc pin");
}
