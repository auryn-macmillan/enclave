# Fair Combinatorial Auction (Threshold FHE Solver Competition)

A sealed-bid **fair combinatorial auction** for solver competition where solvers submit encrypted bids on batches of public user trade intents. A **2-of-3 committee** executes a 4-round protocol that uses progressive public decryption of sign bits to determine the winning solver and their second-price reward while preserving the privacy of losing scores.

## Quick start

```bash
cargo run --bin demo --release
```

This generates synthetic trade intents and solver bids, runs the full threshold FHE pipeline, and asserts the result against a plaintext shadow.

## How it works

### 1. Committee DKG

Three committee members run a distributed key generation protocol to establish a joint public key without a trusted dealer. Each member samples a BFV secret key and contributes a public key share. The joint key is used by solvers to encrypt their bids. No single member knows the full secret key, which is only usable for decryption if a threshold of members (2-of-3) cooperate.

### 2. Encoding: One-Ciphertext-per-Solver SIMD

Solvers encode their bids using **SIMD packing** without bit-decomposition. Each of the 8 directed trading pair scores is mapped to a specific SIMD slot in a single BFV plaintext.

*   **One Ciphertext per Solver**: A solver's entire bid is contained in one ciphertext.
*   **Multiplicative Depth 0**: Comparisons are performed by subtracting two ciphertexts and decrypting the result. Because BFV addition and subtraction are native operations, the circuit depth is zero.
*   **Efficiency**: Packed encoding reduces the number of threshold decryptions and input validation proofs compared to per-pair ciphertexts.

### 3. Sign-Bit Convention

To compare scores without full decryption, the protocol uses a sign-bit convention over the BFV plaintext modulus $t = 12289$. All scores are constrained to the range $[0, 6000]$. When decrypting the difference between two scores, the resulting value indicates the relative ordering:

*   **Positive (Greater)**: $v \in [1, 6144)$
*   **Equal**: $v = 0$
*   **Negative (Less)**: $v \in [6144, 12289)$

This ensures that the difference between any two valid scores never wraps around the modulus, allowing for unambiguous comparisons.

### 4. Progressive Settlement Protocol

The auction follows a 4-round protocol that filters for fairness before selecting a winner.

#### Round 1: Reference Outcome
The committee determines the best single-pair bid for each directed pair independently via a sequential tournament of all solvers. This establishes a baseline of the best possible individual outcomes.

#### Round 2: Fairness Filter
The committee filters out any solver whose "batched" bid (the total solution they provided) makes any single pair worse off than the Round 1 reference outcome. A solver survives only if their score for every pair is greater than or equal to the reference score for that pair.

**Fallback Behavior**: If no solver survives Round 2, the protocol falls back to the Round 1 reference outcome. In this case, Rounds 3 and 4 are explicitly skipped.

#### Round 3: Winner Selection
From the survivors of Round 2, the committee identifies the solver with the highest **total score** (sum of scores across all pairs) using sequential comparisons of aggregate differences.

#### Round 4: Second-Price Reward
The winning solver receives a reward based on the second-price mechanism. Their reward is the total score of the runner-up survivor. If only one solver survived the fairness filter, the second price is set to the total score of the reference outcome.

## What is revealed vs. what stays hidden

| Data | Revealed? | When? | Why? |
|------|-----------|-------|------|
| Best solver indices per pair | ✅ Yes | Round 1 | Establishes the reference outcome baseline |
| Set of "fair" solvers | ✅ Yes | Round 2 | Identifies which solvers pass the fairness check |
| Identity of winning solver | ✅ Yes | Round 3 | Determines the winner of the batched auction |
| Total score of runner-up | ✅ Yes | Round 4 | Sets the second-price reward for the winner |
| Individual solver scores | ❌ No | Never | Only relative rankings and aggregate sums are revealed |
| Per-pair score differences | ❌ Partially | During comparisons | Relative ordering is revealed through sign-bit decryption |

### Trust model

This demo assumes the decrypting 2-of-3 committee follows the protocol and only decrypts the authorized comparison results. The progressive decryption flow narrows what an honest committee learns, but it is not cryptographic access control against a colluding threshold quorum.

## Production considerations

### No evaluation keys needed

Because the entire protocol is multiplicative depth 0 and does not require rotations, **distributed eval-key MPC is unnecessary**. The committee only needs to perform DKG for the primary encryption key, significantly simplifying the setup.

### Smudging noise

Every threshold decryption includes smudging noise (λ = 80 bits) to prevent secret key leakage. This noise drowns out any key-dependent components in the decryption shares, providing statistical security for the joint secret.

## Project structure

```
src/
├── lib.rs          Core library: encoding, sign-bit logic, 4-round protocol
└── bin/
    └── demo.rs     15-solver demo with 2-of-3 committee and fairness filtering
```

## BFV parameters

| Parameter | Value | Notes |
|-----------|-------|-------|
| N (degree) | 2048 | Supports up to 2048 SIMD slots (demo uses 8) |
| t (plaintext mod) | 12289 | Used for sign-bit convention over [0, 6000] range |
| Moduli | 6 × 62-bit | Standard BFV moduli for depth 0 operations |

## Threshold parameters

| Parameter | Value | Notes |
|-----------|-------|-------|
| Committee size (n) | 3 | Total number of committee members |
| Threshold (t) | 1 | Reconstruction requires 2 parties |
| Smudging λ | 80 bits | Statistical security for noise flooding |
