# Fair Combinatorial Auction: Progressive Public Decryption

This example implements a **fair combinatorial auction** for solver competition, inspired by the Canidio-Henneke mechanism (arXiv 2408.12225v3) and CoW Protocol's CIP-67. The auction allows solvers to submit encrypted bids on batches of public user trade intents. A 4-round protocol uses progressive public decryption of sign bits to determine the winning solver and their second-price reward while preserving the privacy of losing scores.

## Overview

In a fair combinatorial auction, solvers compete to provide the best execution for a batch of trades. Unlike a standard auction where only the total surplus matters, a "fair" auction ensures that no individual trade is worse off than it would have been under a reference outcome (e.g., the best single-pair price).

This implementation uses threshold BFV fully homomorphic encryption to allow solvers to submit their bids privately. The committee then executes a protocol that reveals only the minimum information necessary to identify the winner and satisfy the fairness constraints.

## Participants

*   **Users**: Submit public trade intents (e.g., "Swap 1 ETH for DAI").
*   **Solvers**: Observe public intents and submit encrypted bids. A bid consists of a vector of "surplus" scores for each trading pair.
*   **Committee**: A 2-of-3 threshold group that performs the DKG and threshold decryption.

## Public Synthetic Intents

For the demo, we generate synthetic intents across 8 directed trading pairs (e.g., ETH/DAI, DAI/ETH, etc.). These intents provide the context for solver bidding.

## Encoding Scheme: Packed SIMD Scores

Solvers encode their bids using **SIMD packing** without bit-decomposition. Each of the 8 directed pair scores is mapped to a specific SIMD slot in a single BFV plaintext.

*   **One Ciphertext per Solver**: A solver's entire bid is contained in one ciphertext.
*   **Multiplicative Depth 0**: Comparisons are performed by subtracting two ciphertexts (`CT_a - CT_b`) and decrypting the result. Since BFV addition/subtraction is a native operation, the circuit depth is zero.
*   **Efficiency**: Packed encoding reduces the number of threshold decryptions and input validation proofs compared to per-pair ciphertexts.

## Sign-Bit Convention

To compare scores without full decryption, we use a sign-bit convention over the BFV plaintext modulus $t = 12289$.

*   **Score Range**: All scores must be in the range $[0, 6000]$.
*   **Positive (Greater)**: A decrypted value $v \in [1, 6144)$ indicates the first score was greater.
*   **Equal**: A value $v = 0$.
*   **Negative (Less)**: A value $v \in [6144, 12289)$ indicates the second score was greater.

The boundary $t/2 = 6144.5$ ensures that the difference between any two valid scores ($[-6000, 6000]$) never wraps around the modulus in a way that creates ambiguity.

## BFV Parameter Constraints

The protocol uses specific BFV parameters to support efficient depth 0 comparisons while maintaining unambiguous sign bits.

*   **Degree (N)**: 2048. This supports up to 2048 SIMD slots, though the demo uses only the first 8 for trading pairs.
*   **Plaintext Modulus (t)**: 12289. This is a standard BFV prime that supports SIMD operations.
*   **Score Range**: $[0, 6000]$. By constraining input scores to this range, any difference between two scores $s_1 - s_2$ falls within $[-6000, 6000]$.
*   **Centered Differences**: After decryption, a value $v$ is interpreted as $v$ if $v < t/2$ (positive) and $v - t$ if $v \ge t/2$ (negative). With $t=12289$, the boundary is $6144.5$. Since our maximum difference is $6000$, there is no risk of modular wrap-around causing a positive difference to appear negative or vice versa.

## Comparison to CoW CIP-67

This implementation is a proof-of-concept (PoC) for a combinatorial auction as described in the Canidio-Henneke paper and CoW Protocol's CIP-67.

### What it Matches
*   **Fairness Constraint**: It enforces that no individual pair is worse off than its best single-pair execution (the reference outcome).
*   **Tournament Structure**: It uses a sequential comparison (tournament) to find the best bids without revealing all scores.
*   **Surplus Maximization**: The objective is to maximize the aggregate surplus across all pairs for the winning solver.

### Intentional Simplifications
*   **Static Pairs**: The demo uses 8 fixed trading pairs rather than dynamic sets of intents.
*   **No Multi-Token Rings**: It focuses on directed pairs rather than complex ring trades, though the encoding could be extended to support them.
*   **Linear Scoring**: It uses a simplified integer surplus score rather than complex fee/gas-adjusted utility functions.
*   **Public Decryption**: It uses threshold decryption to make results public to the committee and participants, whereas a production system might integrate this with a ZKP-verified state transition on-chain.

## 4-Round Protocol

### Round 1: Reference Outcome
The committee determines the best single-pair bid for each directed pair independently. This is done via a sequential scan (tournament) of all solvers. 
*   **Input**: All solver ciphertexts.
*   **Process**: For each pair, find the solver with the highest score.
*   **Output**: A reference vector of best solver indices per pair.

### Round 2: Fairness Filter
The committee filters out any solver whose "batched" bid (the total solution they provided) makes any single pair worse off than the reference outcome.
*   **Criteria**: A solver survives if their score for every pair is $\ge$ the reference score for that pair.
*   **Fallback**: If no solver survives Round 2, the protocol falls back to the Round 1 reference outcome. Rounds 3 and 4 are skipped.

### Round 3: Winner Selection
From the survivors of Round 2, the committee identifies the solver with the highest **total score** (sum of scores across all pairs).

*   **Process**:
    1.  The committee picks a candidate "incumbent" survivor.
    2.  For each "challenger" survivor, compute the difference ciphertext $CT_{diff} = CT_{challenger} - CT_{incumbent}$.
    3.  Threshold-decrypt $CT_{diff}$ to obtain a plaintext with packed differences in the SIMD slots.
    4.  The committee interprets each SIMD slot as a centered difference (mapping values $\ge t/2$ to negative integers).
    5.  The sum of these 8 differences is calculated in plaintext.
    6.  If the sum is positive, the challenger becomes the new incumbent.
*   **Leakage Note**: This approach leaks the total score difference between survivors during the tournament, as well as the per-pair differences. This is an accepted trade-off for the simplicity of depth 0 operations.
*   **Output**: A single winning solver.

### Round 4: Second-Price Reward
The winning solver receives a reward based on the second-price mechanism.
*   **Calculation**: The winner's "price" is the total score of the runner-up survivor. 
*   **Single Survivor Case**: If only one solver survived the fairness filter, the second price is the total score of the reference outcome.

## Privacy Analysis

| Round | Information Revealed | Privacy Guarantee |
|-------|----------------------|-------------------|
| Round 1 | Indices of best solvers per pair | Individual scores remain encrypted. Relative rankings are partially leaked during tournament. |
| Round 2 | Set of "fair" solvers | Which solvers failed the fairness check and on which pairs. |
| Round 3 | Identity of the winning solver | Per-pair score differences between survivors are leaked during total score comparison. |
| Round 4 | Total score of the runner-up | Only the aggregate runner-up score is revealed. |

All decryptions in this protocol are **public**. The committee reveals the results to all participants.

## Depth Analysis

The entire protocol is **Multiplicative Depth 0**.
*   **Subtraction**: $CT_a - CT_b$ is a native addition-style operation.
*   **Threshold Decryption**: Linear operation on shares.
*   **No Multiplications**: No $ct \times ct$ or $ct \times pt$ multiplications are required for the core comparison logic.
*   **No Rotations**: SIMD slots are accessed directly after decryption.

Because the depth is 0, **eval-key MPC is unnecessary**. The committee only needs to perform DKG for the primary encryption key.

## Edge Cases

*   **Ties**: In any comparison (Round 1 or Round 3), the solver with the lower index wins the tie.
*   **Empty Survivor Fallback**: If no solver passes the fairness filter, the Round 1 reference outcome (the collection of best individual pair bids) is used as the final settlement.
*   **Single Survivor**: If exactly one solver survives Round 2, they win automatically. The second price is set to the total score of the reference outcome.

## Usage Context

All commands and development should be performed from the `examples/combinatorial-auction/` directory.

```bash
cargo run --bin demo --release
```
