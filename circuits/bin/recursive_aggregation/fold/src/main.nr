// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use bb_proof_verification::{UltraHonkProof, UltraHonkVerificationKey, verify_honk_proof_non_zk};
use lib::math::poseidon2_commitment::{compute_recursive_aggregation_commitment, compute_vk_hash};

fn main(
    proof1_verification_key: UltraHonkVerificationKey,
    proof1_proof: UltraHonkProof,
    proof1_public_inputs: [Field; 2],
    proof1_key_hash: Field,
    proof2_verification_key: UltraHonkVerificationKey,
    proof2_proof: UltraHonkProof,
    proof2_public_inputs: [Field; 2],
    proof2_key_hash: Field,
) -> pub (Field, Field) {
    verify_honk_proof_non_zk(
        proof1_verification_key,
        proof1_proof,
        proof1_public_inputs,
        proof1_key_hash,
    );
    verify_honk_proof_non_zk(
        proof2_verification_key,
        proof2_proof,
        proof2_public_inputs,
        proof2_key_hash,
    );

    // Hash the two commitments with Poseidon so the verifier can check the folded proof used the expected public inputs.
    let commitment = compute_recursive_aggregation_commitment([
        proof1_public_inputs[1],
        proof2_public_inputs[1],
    ]);

    // Hash the full VK chain: attested key hashes from inner proofs (public_inputs[0]) plus the VKs
    // that verified them (proof*_key_hash). This combined fingerprint lets the verifier check the
    // entire proof genealogy: which circuits were folded and which verified each level.
    let key_hash = compute_vk_hash([
        proof1_public_inputs[0], // key_hash attested by proof1 (from its inner folds)
        proof2_public_inputs[0], // key_hash attested by proof2 (from its inner folds)
        proof1_key_hash, // VK hash of circuit that produced proof1
        proof2_key_hash, // VK hash of circuit that produced proof2
    ]);

    (key_hash, commitment)
}
