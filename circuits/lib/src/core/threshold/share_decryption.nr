// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::math::poseidon2_commitment::compute_aggregated_shares_commitment;
use crate::math::helpers::flatten_arr;
use crate::math::polynomial::Polynomial;
use std::phase::challenge_slice;

/// Cryptographic parameters for Threshold decryption share circuit.
pub struct Configs<let L: u32> {
    /// CRT moduli: [q_0, q_1, ..., q_{L-1}]
    pub qis: [Field; L],
    /// Bounds for r1 polynomials (modulus switching quotients) for each CRT basis
    pub r1_bounds: [Field; L],
    /// Bounds for r2 polynomials (cyclotomic reduction quotients) for each CRT basis
    pub r2_bounds: [Field; L],
}

impl<let L: u32> Configs<L> {
    pub fn new(qis: [Field; L], r1_bounds: [Field; L], r2_bounds: [Field; L]) -> Self {
        Configs { qis, r1_bounds, r2_bounds }
    }
}

/// Threshold Share Decryption (Circuit 6).
///
/// Verifies:
/// 1. Commitment to sk matches expected (from DKG decryption circuit)
/// 2. Commitment to e_sm matches expected (from DKG decryption circuit)
/// 3. Correct computation: d_i = c_0i + c_1i * s_i + e_i + r_2i * (X^N + 1) + r_1i * q_i
pub struct ShareDecryption<let N: u32, let L: u32, let BIT_CT: u32, let BIT_SK: u32, let BIT_E_SM: u32, let BIT_R1: u32, let BIT_R2: u32, let BIT_D: u32> {
    /// Circuit parameters including bounds and cryptographic constants
    configs: Configs<L>,

    /// Expected commitment to aggregated sk shares (from DKG decryption circuit)
    /// (public witness)
    expected_sk_commitment: Field,

    /// Expected commitment to aggregated e_sm shares (from DKG decryption circuit)
    /// (public witness)
    expected_e_sm_commitment: Field,

    /// Ciphertext components (public witnesses)
    /// ct0 components for each CRT basis (degree N-1 polynomials with N coefficients)
    ct0: [Polynomial<N>; L],
    /// ct1 components for each CRT basis (degree N-1 polynomials with N coefficients)
    ct1: [Polynomial<N>; L],

    /// Aggregated sum of sk shares (secret witness)
    sk: [Polynomial<N>; L],

    /// Aggregated sum of e_sm shares (secret witness, direct input)
    /// e_sm[basis] - sum of e_sm shares for each CRT basis (degree N-1 with N coefficients)
    e_sm: [Polynomial<N>; L],

    /// Quotient polynomials for lifting to Z (secret witnesses)
    r1: [Polynomial<2 * N - 1>; L],
    r2: [Polynomial<N - 1>; L],

    /// Party's computed decryption share
    /// (public witnesses)
    d: [Polynomial<N>; L],
}

impl<let N: u32, let L: u32, let BIT_CT: u32, let BIT_SK: u32, let BIT_E_SM: u32, let BIT_R1: u32, let BIT_R2: u32, let BIT_D: u32> ShareDecryption<N, L, BIT_CT, BIT_SK, BIT_E_SM, BIT_R1, BIT_R2, BIT_D> {
    pub fn new(
        configs: Configs<L>,
        expected_sk_commitment: Field,
        expected_e_sm_commitment: Field,
        ct0: [Polynomial<N>; L],
        ct1: [Polynomial<N>; L],
        sk: [Polynomial<N>; L],
        e_sm: [Polynomial<N>; L],
        r1: [Polynomial<2 * N - 1>; L],
        r2: [Polynomial<N - 1>; L],
        d: [Polynomial<N>; L],
    ) -> Self {
        ShareDecryption {
            configs,
            expected_sk_commitment,
            expected_e_sm_commitment,
            ct0,
            ct1,
            sk,
            e_sm,
            r1,
            r2,
            d,
        }
    }

    /// Verifies that aggregated secret shares hash to expected_sk_commitment
    fn verify_agg_sk_commitment(self) {
        assert(
            compute_aggregated_shares_commitment::<N, L, BIT_SK>(self.sk)
                == self.expected_sk_commitment,
            "S commitment mismatch",
        );
    }

    /// Verifies that aggregated noise shares hash to expected_e_sm_commitment
    fn verify_agg_e_sm_commitment(self) {
        assert(
            compute_aggregated_shares_commitment::<N, L, BIT_E_SM>(self.e_sm)
                == self.expected_e_sm_commitment,
            "E commitment mismatch",
        );
    }

    /// Main verification function
    pub fn execute(self) {
        // Step 1: Verify sk commitment matches expected
        self.verify_agg_sk_commitment();

        // Step 2: Verify e_sm commitment matches expected
        self.verify_agg_e_sm_commitment();

        // Step 3: Perform range checks on quotient polynomials
        self.check_range_bounds();

        // Step 4: Generate Fiat-Shamir challenge via backend commitment
        let gamma = self.generate_challenge();

        // Step 5: Verify decryption share computation for each CRT basis
        for i in 0..L {
            self.verify_decryption_share_computation(i, gamma);
        }
    }

    /// Performs range checks on quotient polynomial witnesses.
    fn check_range_bounds(self) {
        for basis_idx in 0..L {
            self.r1[basis_idx].range_check_2bounds::<BIT_R1>(
                self.configs.r1_bounds[basis_idx],
                self.configs.r1_bounds[basis_idx],
            );
            self.r2[basis_idx].range_check_2bounds::<BIT_R2>(
                self.configs.r2_bounds[basis_idx],
                self.configs.r2_bounds[basis_idx],
            );
        }
    }

    /// Derives the Fiat-Shamir challenge via the proving backend's KZG commitment
    /// and Poseidon2 transcript, replacing the in-circuit SAFE sponge.
    ///
    /// Uses challenge_slice to accept a dynamically-built payload vector,
    /// avoiding massive compile-time type expressions that cause compiler hangs.
    ///
    /// Payload order: [sk_commit, e_sm_commit, packed(ct0), packed(ct1),
    ///                 packed(r1), packed(r2), packed(d)]
    fn generate_challenge(self) -> Field {
        let packed_ct0 = flatten_arr::<_, _, BIT_CT>(self.ct0);
        let packed_ct1 = flatten_arr::<_, _, BIT_CT>(self.ct1);
        let packed_r1 = flatten_arr::<_, _, BIT_R1>(self.r1);
        let packed_r2 = flatten_arr::<_, _, BIT_R2>(self.r2);
        let packed_d = flatten_arr::<_, _, BIT_D>(self.d);

        let mut payload: [Field] = &[];
        payload = payload.push_back(self.expected_sk_commitment);
        payload = payload.push_back(self.expected_e_sm_commitment);
        for i in 0..packed_ct0.len() {
            payload = payload.push_back(packed_ct0[i]);
        }
        for i in 0..packed_ct1.len() {
            payload = payload.push_back(packed_ct1[i]);
        }
        for i in 0..packed_r1.len() {
            payload = payload.push_back(packed_r1[i]);
        }
        for i in 0..packed_r2.len() {
            payload = payload.push_back(packed_r2[i]);
        }
        for i in 0..packed_d.len() {
            payload = payload.push_back(packed_d[i]);
        }

        challenge_slice(payload)
    }

    /// Verifies the lifted decryption share computation formula for a specific CRT basis.
    fn verify_decryption_share_computation(self, basis_idx: u32, gamma: Field) {
        let c_0_at_gamma = self.ct0[basis_idx].eval(gamma);
        let c_1_at_gamma = self.ct1[basis_idx].eval(gamma);
        let sk_at_gamma = self.sk[basis_idx].eval(gamma);
        let e_sm_at_gamma = self.e_sm[basis_idx].eval(gamma);
        let r_1_at_gamma = self.r1[basis_idx].eval(gamma);
        let r_2_at_gamma = self.r2[basis_idx].eval(gamma);
        let cyclo_at_gamma = gamma.pow_32(N as Field) + 1;

        let expected_decryption_share = c_0_at_gamma
            + c_1_at_gamma * sk_at_gamma
            + e_sm_at_gamma
            + r_2_at_gamma * cyclo_at_gamma
            + r_1_at_gamma * self.configs.qis[basis_idx];

        let computed_decryption_share = self.d[basis_idx].eval(gamma);

        assert(
            computed_decryption_share == expected_decryption_share,
            "Decryption share computation failed",
        );
    }
}
