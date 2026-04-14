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

### 2. Encoding: cumulative demand vectors

Bidders encode their `(quantity, price)` pair as a step-function vector in SIMD slots 0..63. Slot `p` holds the quantity if the bidder's price is at or above price level `p`, and zero otherwise. This allows the aggregator to sum all ciphertexts into a single aggregate demand curve with zero multiplicative depth.

### 3. Adjacent-difference transform: one-hot conversion

To support carry-forward, the aggregator homomorphically converts cumulative demand ciphertexts into **one-hot price-quantity vectors**. The transform `B_i[p] = V_i[p] - V_i[p+1]` isolates the quantity at the specific price slot. This is computed via one column rotation and a zero-guard mask to prevent cyclic wraparound, consuming zero multiplicative depth.

### 4. Aggregation and clearing

The aggregator sums the one-hot ciphertexts into an **aggregate histogram**. The committee threshold-decrypts this histogram to find the clearing price $P^*$—the highest price where total demand meets or exceeds supply. Plaintext suffix-sums on the decrypted histogram recover the full demand curve.

### 5. Order classification and allocation

Using the public clearing index $k$, the committee classifies each order:
1. **Strict winners** (price > $P^*$): Fully filled. Committee decrypts one slot for allocation reporting and drops the ciphertext.
2. **Strict losers** (price < $P^*$): Unfilled. Ciphertext is carried forward untouched with zero per-order information revealed.
3. **Marginal** (price = $P^*$): Partially filled. Committee decrypts the quantity slot, computes pro-rata in plaintext, and re-encrypts the residual.

### 6. Multi-round carry-forward

FBA uses **epoch-based priority** where earlier-round orders fill first at the marginal price. The committee re-encrypts marginal residuals for the next epoch's book. Bidders never interact after their initial submission, enabling a "submit once, match eventually" workflow.

## Production considerations

### Distributed evaluation keys

The adjacent-difference transform requires column rotations, which depend on a joint Galois key. This demo uses the repo's distributed eval-key MPC protocol, ensuring the committee generates rotation and relinearization keys without ever reconstructing the joint secret key.

### Smudging noise

Threshold decryption shares include **80-bit smudging noise** to protect the secret key from leakage during the multi-round process. While each operation is depth 0, the noise budget is monitored over rounds to ensure long-lived loser ciphertexts remain decryptable.

## Project structure

```
src/
├── lib.rs          Core library: one-hot transform, masks, FBA allocation logic
└── bin/
    └── demo.rs     3-round FBA demo with carry-forward, cancellation, and shadow verification
```

## BFV parameters

| Parameter | Value | Notes |
|-----------|-------|-------|
| N (degree) | 2048 | = 2 rows of 1024 SIMD slots |
| t (plaintext mod) | 12289 | Supports additive aggregation |
| Moduli | 6 × 62-bit | Sufficient for rotations and multiple rounds |
| Price levels | 64 | Discrete ladder 0..63 |

## Threshold parameters

| Parameter | Value | Notes |
|-----------|-------|-------|
| Committee size (n) | 3 | 2-of-3 threshold setup |
| Threshold (t) | 1 | Any 2 members can reconstruct |
| Smudging λ | 80 bits | Statistical security for noise flooding |
