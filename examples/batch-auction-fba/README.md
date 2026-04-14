# Frequent Batch Auction (Threshold FHE Multi-Round Demo)

A periodic **Frequent Batch Auction (FBA)** where orders accumulate in encrypted form and match simultaneously at the end of each discrete time window. A **2-of-3 committee** jointly determines the clearing price and allocations via threshold BFV, using a hybrid carry-forward design where orders persist across multiple epochs without further bidder interaction.

## Quick start

```bash
cargo run --bin demo --release
```

This runs a 3-round simulation with 10 bidders, including order carry-forward and cancellation, asserting all FHE results against a plaintext shadow.

## How it works

### 1. Committee DKG (distributed key generation)

Three committee members run a distributed key generation protocol to create a **joint public key** without a trusted dealer. Each member samples a secret key, computes a public key share, and Shamir-splits their secret for distribution. Bidders encrypt only once to the joint key; no single member can decrypt individual orders.

### 2. Encoding: multi-coefficient demand vectors

Bidders encode their `(quantity, price)` pair using a high-throughput **multi-coefficient polynomial encoding** (`Encoding::poly()`). Each price level spans `SLOT_WIDTH = 16` polynomial coefficients, where each coefficient holds one bit of the quantity's binary representation. This allows for massive aggregation while maintaining a constant multiplicative depth of zero.

### 3. Aggregation and clearing

The aggregator sums all active ciphertexts into an **aggregate demand curve**. Because each coefficient represents a bit-count across all bidders, the committee can threshold-decrypt this aggregate and decode the total demand at every price level using `decode_demand_curve()`. The clearing price $P^*$ is the highest price where total demand meets or exceeds supply.

### 4. Order classification and allocation

Using the public clearing index $k$, the committee classifies each order:
1. **Strict winners** (price > $P^*$): Fully filled. Committee threshold-decrypts the relevant price-level block for allocation reporting and drops the ciphertext.
2. **Strict losers** (price < $P^*$): Unfilled. Ciphertext is carried forward untouched with zero per-order information revealed.
3. **Marginal** (price = $P^*$): Partially filled. Committee threshold-decrypts the marginal quantity block, computes pro-rata in plaintext, and re-encrypts the residual.

### 5. Multi-round carry-forward

FBA uses **epoch-based priority** where earlier-round orders fill first at the marginal price. The committee re-encrypts marginal residuals for the next epoch's book using `encrypt_residual`. Bidders never interact after their initial submission, enabling a "submit once, match eventually" workflow.

## Production considerations

### Distributed evaluation keys

While the core FBA pipeline under poly-encoding uses pure ciphertext additions and threshold decryption, the repository's distributed eval-key MPC infrastructure remains fully integrated. This ensures that any additional mechanisms requiring Galois rotations or relinearization can be securely executed without ever reconstructing the joint secret key.

### Smudging noise

Threshold decryption shares include **80-bit smudging noise** to protect the secret key from leakage during the multi-round process. Because the pipeline avoids depth-consuming operations like rotations and multiplications, the noise growth is minimal, allowing for a large number of carry-forward rounds.

## Project structure

```
src/
├── lib.rs          Core library: classification masks, allocation logic, decryption/encryption helpers
└── bin/
    └── demo.rs     3-round FBA demo with carry-forward, cancellation, and shadow verification
```

## BFV parameters

| Parameter | Value | Notes |
|-----------|-------|-------|
| N (degree) | 2048 | 128 max price levels with SLOT_WIDTH=16 (demo uses 64) |
| t (plaintext mod) | 12289 | Must exceed z (bidder count) for bit-position counts |
| Moduli | 6 × 62-bit | Sufficient for multiple rounds and slow noise growth |
| Price levels | 64 | Discrete ladder 0..63 |

## Threshold parameters

| Parameter | Value | Notes |
|-----------|-------|-------|
| Committee size (n) | 3 | 2-of-3 threshold setup |
| Threshold (t) | 1 | Any 2 members can reconstruct |
| Smudging λ | 80 bits | Statistical security for noise flooding |
