// SPDX-License-Identifier: LGPL-3.0-only
//
// r141 e_par — option (a) SIZING, LEG 1 (K=12 2-pt slope point): base
// cheap-verify cell (r137 w-class: reversed -> flatten::<N,1,58> -> running-
// acc pin) + ONE Reed-Solomon parity row per cell over the FULL cell
// payload. Shape-probe: the H-row value is a dummy small constant — the
// question is whether the per-cell (acc + parity) shape compiles at the A
// production shape and what the parity-row overhead is, vs the r137 base
// twins (w6 = 16,409 g, w12 = 32,801 g).
// The producer carries H-rows as public witness constants (share_
// computation.nr `h: [[[Field; N_PARTIES + 1]; N_PARTIES - T]; L]`); this
// probe carries the row as a public scalar because every row entry is
// equal (constant-folded row) — the arithmetic is bit-identical to one
// H[col] * payload[col] dot row, and the wrap-safe bound is the producer's
// own (share_computation.nr L295: |sum| < (N_PARTIES+1)*max(h)*q_j).
// Here: |sum| < 8247 * 5 = 41,235 << field prime.
use lib::configs::default::dkg::{N, SHARE_DECRYPTION_BIT_MSG};
use lib::math::helpers::flatten;
use lib::math::modulo::U64::ModU64;
use lib::math::polynomial::Polynomial;

fn main(
    shares: [Polynomial<N>; 42],
    q: pub [Field; 3],
    h: pub [Field; 3],
    expected: pub [Field; 42],
) {
    for k in 0..42 {
        let mut reversed_coeffs: [Field; N] = [0; N];
        for i in 0..N {
            reversed_coeffs[N - 1 - i] = shares[k].coefficients[i];
        }
        let payload = flatten::<N, 1, SHARE_DECRYPTION_BIT_MSG>(
            [].as_vector(),
            [Polynomial::new(reversed_coeffs)],
        );
        let mut acc = 0;
        let len = payload.len();
        for i in 0..len {
            acc = acc * 3641542188856621199 + payload[i];
        }
        assert(acc == expected[k], "payload pin");
        // ONE parity row: sum_j h[0] * payload_j == 0 (mod q[0]) —
        // the producer's assert_zero_mod pattern verbatim (L294-296).
        let mut s = 0;
        for j in 0..len {
            s = s + h[0] * payload[j];
        }
        ModU64::new(q[0] as u64).assert_zero_mod(s);
    }
}