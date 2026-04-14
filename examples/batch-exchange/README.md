# Two-Sided Batch Exchange (Threshold FHE Demand-Supply Demo)

A sealed-bid **two-sided batch exchange** for a single trading pair where both buy and sell orders are encrypted under threshold BFV fully-homomorphic encryption. A **2-of-3 committee** jointly determines the clearing price by intersecting aggregate demand and supply curves, then threshold-decrypts per-participant allocations without revealing individual order details.

## Quick start

```bash
cargo run --bin demo --release
```

This generates 5 random buyers and 5 random sellers, runs the full threshold FHE pipeline, and asserts the result against a plaintext shadow.

## How it works

### 1. Committee DKG

Three committee members run a distributed key generation protocol to establish a joint public key without a trusted dealer. Each member samples a BFV secret key and contributes a public key share. The joint key is used by all participants to encrypt their orders. No single member knows the full secret key, which is only usable for decryption if a threshold of members (2-of-3) cooperate.

### 2. Encoding: Two-Sided Step Functions

The exchange uses a public grid of 64 discrete price levels. Participants encode their orders into BFV SIMD slots corresponding to these price levels:

*   **Buyers** (Demand): Encode a **descending step function**. A buyer with `(quantity, max_price)` places `quantity` in all slots where the price level is less than or equal to `max_price`, and 0 elsewhere.
*   **Sellers** (Supply): Encode an **ascending step function**. A seller with `(quantity, min_price)` places `quantity` in all slots where the price level is greater than or equal to `min_price`, and 0 elsewhere.

This encoding moves the comparison logic into the client-side pre-processing phase, allowing the matching engine to operate with additive FHE.

### 3. Accumulation: Curve Summation

The aggregator maintains two separate encrypted accumulators. It sums all buyer ciphertexts into an aggregate **buy demand curve** and all seller ciphertexts into an aggregate **sell supply curve**. Because BFV addition is native, this accumulation happens at **multiplicative depth 0**.

### 4. Threshold Decryption of Curves

The committee threshold-decrypts both aggregate curves. Since these curves only reveal the total volume demanded or supplied at each price level, the privacy of individual participant prices and quantities is preserved.

### 5. Clearing Price Computation

The committee identifies the clearing price by performing a descending scan of the decrypted curves. The clearing price is the highest price level where:
1. Aggregate buy demand is greater than or equal to aggregate sell supply.
2. Aggregate sell supply is greater than zero.

If the curves do not intersect, the clearing price returns `None` and no trades occur.

### 6. Rationing and Allocation

Once the clearing price index `k` is found, the committee determines which side is rationed:
*   If `demand > supply` at the clearing price, buyers are rationed.
*   If `supply > demand`, sellers are rationed.

To extract per-participant quantities, the committee threshold-decrypts masked versions of the original input ciphertexts. Buyers use slots `(k, k+1)` to distinguish strict winners from marginal demand. Sellers use slots `(k, k-1)` (or just `k` at the lowest price). Pro-rata allocation with largest-remainder rounding is applied only to the rationed side.

## Production considerations

### Distributed evaluation keys

This demo uses the repository's distributed eval-key MPC flow to generate Galois and relinearization keys. The joint secret key is never reconstructed, ensuring that the committee can perform rotations and relinearization securely across separate nodes.

### Smudging noise

Every threshold decryption includes smudging noise (λ = 80 bits) to prevent secret key leakage. This noise drowns out any key-dependent components in the decryption shares, providing statistical security for the joint secret.

### Multi-pair extension

This example demonstrates a single trading pair (Asset A / Asset B). The architecture serves as a foundation for multi-pair combinatorial matching, where clearing prices across multiple pairs are solved simultaneously.

## Project structure

```
src/
├── lib.rs          Core library: encoding, curve intersection, allocation logic
└── bin/
    └── demo.rs     5-buyer, 5-seller demo with 2-of-3 committee and verification
```

## BFV parameters

| Parameter | Value | Notes |
|-----------|-------|-------|
| N (degree) | 2048 | 2048 SIMD slots |
| t (plaintext mod) | 12289 | Sum of quantities must be < 6144 |
| Moduli | 6 × 62-bit | Sufficient for rotations and masking |
| Price levels | 64 | Discrete price grid size |

## Threshold parameters

| Parameter | Value | Notes |
|-----------|-------|-------|
| Committee size (n) | 3 | Total number of committee members |
| Threshold (t) | 1 | Reconstruction requires 2 parties |
| Smudging λ | 80 bits | Statistical security for noise flooding |
