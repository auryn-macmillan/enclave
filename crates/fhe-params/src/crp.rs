// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Common Random Polynomial (CRP) construction from BFV parameters.

use fhe::bfv::BfvParameters;
use fhe::mbfv::CommonRandomPoly;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use sha2::{Digest, Sha256};
use std::sync::Arc;

const EVAL_KEY_CRS_LABEL: &[u8] = b"e3-fhe-params/eval-key-crs/v1";
const RELIN_DOMAIN_LABEL: &[u8] = b"relin";
const GALOIS_DOMAIN_LABEL: &[u8] = b"galois";

pub type EvalKeyRootSeed = [u8; 32];

pub type EvalKeyDerivedSeed = [u8; 32];

/// Creates a Common Random Polynomial for the given BFV parameters and seed.
pub fn create_deterministic_crp_from_seed(
    params: &Arc<BfvParameters>,
    seed: [u8; 32],
) -> CommonRandomPoly {
    CommonRandomPoly::new_deterministic(&params, seed).unwrap()
}

/// Creates a Common Random Polynomial for the given BFV parameters and default seed.
pub fn create_deterministic_crp_from_default_seed(params: &Arc<BfvParameters>) -> CommonRandomPoly {
    create_deterministic_crp_from_seed(params, <ChaCha8Rng as SeedableRng>::Seed::default())
}

/// Unused: actual eval-key CRS derivation uses `e3_trbfv::distributed_eval_key::derive_seed`
/// with different domain separation. Kept for potential external tooling.
pub fn derive_relin_crs_seed(root_seed: EvalKeyRootSeed, index: usize) -> EvalKeyDerivedSeed {
    derive_eval_key_seed(
        root_seed,
        RELIN_DOMAIN_LABEL,
        &[(index as u64).to_le_bytes()],
    )
}

pub fn derive_galois_crs_seed(
    root_seed: EvalKeyRootSeed,
    exponent: u64,
    index: usize,
) -> EvalKeyDerivedSeed {
    derive_eval_key_seed(
        root_seed,
        GALOIS_DOMAIN_LABEL,
        &[exponent.to_le_bytes(), (index as u64).to_le_bytes()],
    )
}

fn derive_eval_key_seed(
    root_seed: EvalKeyRootSeed,
    domain: &[u8],
    components: &[[u8; 8]],
) -> EvalKeyDerivedSeed {
    let mut hasher = Sha256::new();
    hasher.update(EVAL_KEY_CRS_LABEL);
    hasher.update([domain.len() as u8]);
    hasher.update(domain);
    hasher.update(root_seed);

    for component in components {
        hasher.update(component);
    }

    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_bfv_params_arc;
    use crate::constants::insecure_512;
    use fhe_traits::Serialize;

    fn test_params() -> Arc<BfvParameters> {
        build_bfv_params_arc(
            insecure_512::DEGREE,
            insecure_512::threshold::PLAINTEXT_MODULUS,
            insecure_512::threshold::MODULI,
            Some(insecure_512::threshold::ERROR1_VARIANCE),
        )
    }

    #[test]
    fn crp_bytes_roundtrip_via_deserialize() {
        let params = test_params();
        let crp = create_deterministic_crp_from_default_seed(&params);
        let bytes = crp.to_bytes();

        let restored = CommonRandomPoly::deserialize(&bytes, &params)
            .expect("CRP deserialization should succeed");
        let restored_bytes = restored.to_bytes();
        assert_eq!(bytes, restored_bytes, "CRP roundtrip should match");
    }

    #[test]
    fn deterministic_crp_same_seed_same_output() {
        let params = test_params();
        let seed = [42u8; 32];

        let crp1 = create_deterministic_crp_from_seed(&params, seed);
        let crp2 = create_deterministic_crp_from_seed(&params, seed);

        assert_eq!(crp1.to_bytes(), crp2.to_bytes());
    }

    #[test]
    fn deterministic_crp_different_seed_different_output() {
        let params = test_params();
        let seed1 = [1u8; 32];
        let seed2 = [2u8; 32];

        let crp1 = create_deterministic_crp_from_seed(&params, seed1);
        let crp2 = create_deterministic_crp_from_seed(&params, seed2);

        assert_ne!(crp1.to_bytes(), crp2.to_bytes());
    }

    #[test]
    fn relin_crs_seed_same_root_and_index_same_output() {
        let root_seed = [7u8; 32];

        assert_eq!(
            derive_relin_crs_seed(root_seed, 3),
            derive_relin_crs_seed(root_seed, 3)
        );
    }

    #[test]
    fn eval_key_crs_seeds_are_domain_separated() {
        let root_seed = [9u8; 32];

        let relin_seed = derive_relin_crs_seed(root_seed, 2);
        let galois_seed = derive_galois_crs_seed(root_seed, 17, 2);
        let different_galois_exponent = derive_galois_crs_seed(root_seed, 19, 2);
        let different_galois_index = derive_galois_crs_seed(root_seed, 17, 3);

        assert_ne!(relin_seed, galois_seed);
        assert_ne!(galois_seed, different_galois_exponent);
        assert_ne!(galois_seed, different_galois_index);
    }

    #[test]
    fn derived_eval_key_seeds_drive_deterministic_crp_output() {
        let params = test_params();
        let root_seed = [11u8; 32];

        let relin_seed = derive_relin_crs_seed(root_seed, 1);
        let galois_seed = derive_galois_crs_seed(root_seed, 27, 1);

        let relin_crp_1 = create_deterministic_crp_from_seed(&params, relin_seed);
        let relin_crp_2 = create_deterministic_crp_from_seed(&params, relin_seed);
        let galois_crp = create_deterministic_crp_from_seed(&params, galois_seed);

        assert_eq!(relin_crp_1.to_bytes(), relin_crp_2.to_bytes());
        assert_ne!(relin_crp_1.to_bytes(), galois_crp.to_bytes());
    }
}
