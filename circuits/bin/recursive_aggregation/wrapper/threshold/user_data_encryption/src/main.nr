// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use bb_proof_verification::{
    UltraHonkProof1Phase, UltraHonkVerificationKey, verify_honk_proof_non_zk_1phase,
};
use lib::math::poseidon2_commitment::{compute_commitment, DS_CIPHERTEXT, DS_PK_AGGREGATION};

fn main(
    // User Data Encryption ct0 Section.
    ct0_verification_key: UltraHonkVerificationKey,
    ct0_proof: UltraHonkProof1Phase,
    ct0_public_inputs: [Field; 4], // pk0_commitment, ct0_commitment, k1_commitment, u_commitment
    ct0_key_hash: pub Field,
    // User Data Encryption ct1 Section.
    ct1_verification_key: UltraHonkVerificationKey,
    ct1_proof: UltraHonkProof1Phase,
    ct1_public_inputs: [Field; 3], // pk1_commitment, ct1_commitment, u_commitment
    ct1_key_hash: pub Field,
) -> pub (Field, Field, Field) {
    verify_honk_proof_non_zk_1phase(
        ct0_verification_key,
        ct0_proof,
        ct0_public_inputs,
        ct0_key_hash,
    );
    verify_honk_proof_non_zk_1phase(
        ct1_verification_key,
        ct1_proof,
        ct1_public_inputs,
        ct1_key_hash,
    );

    // Verify that the u_commitment from the ct0 proof is the same as the u_commitment from the ct1 proof.
    assert(ct0_public_inputs[3] == ct1_public_inputs[2]);

    // Compute the ct commitment.
    let ct_commitment =
        compute_commitment([ct0_public_inputs[1], ct1_public_inputs[1]], DS_CIPHERTEXT);

    // Computes the public key aggregation commitment.
    let pk_commitment = compute_commitment(
        [ct0_public_inputs[0], ct1_public_inputs[0]],
        DS_PK_AGGREGATION,
    );

    let k1_commitment = ct0_public_inputs[2];

    (pk_commitment, ct_commitment, k1_commitment)
}
