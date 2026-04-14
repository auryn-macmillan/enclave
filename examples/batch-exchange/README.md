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

The exchange uses a public grid of 64 discrete price levels. Participants encode their orders using **multi-coefficient polynomial encoding** (`SLOT_WIDTH = 16`, `Encoding::poly()`). Each price level spans 16 polynomial coefficients, and the quantity is bit-decomposed across these coefficients:

*   **Buyers** (Demand): Encode a **descending step function**. A buyer with `(quantity, max_price)` bit-decomposes their quantity into the coefficient blocks for all price levels where the level is less than or equal to `max_price`.
*   **Sellers** (Supply): Encode an **ascending step function**. A seller with `(quantity, min_price)` bit-decomposes their quantity into the coefficient blocks for all price levels where the level is greater than or equal to `min_price`.

This encoding allows for high-throughput aggregation without carries between coefficients and keeps the circuit at **multiplicative depth 0**.

### 3. Accumulation: Curve Summation

The aggregator maintains two separate encrypted accumulators. It sums all buyer ciphertexts into an aggregate **buy demand curve** and all seller ciphertexts into an aggregate **sell supply curve**. Because BFV addition is native and coefficient-wise, this accumulation happens at **multiplicative depth 0**.

### 4. Threshold Decryption of Curves

The committee threshold-decrypts both aggregate curves. Since these curves only reveal the total bit-counts at each coefficient position across price levels, individual participant quantities and prices stay private.

### 5. Clearing Price Computation

The committee identifies the clearing price by performing a descending scan of the decrypted curves. The clearing price is the highest price level where:
1. Aggregate buy demand is greater than or equal to aggregate sell supply.
2. Aggregate sell supply is greater than zero.

If the curves do not intersect, the clearing price returns `None` and no trades occur.

### 6. Rationing and Allocation

Once the clearing price index `k` is found, the committee determines which side is rationed:
*   If `demand > supply` at the clearing price, buyers are rationed.
*   If `supply > demand`, sellers are rationed.

Under multi-coefficient encoding, masking individual ciphertexts with point-wise multiplication doesn't work. Instead, the committee threshold-decrypts the full ciphertexts of relevant participants and extracts the needed coefficient blocks. Buyers use blocks at price levels `(k, k+1)` to distinguish strict winners from marginal demand. Sellers use blocks at price levels `(k, k-1)` (or just `k` at the lowest price). Pro-rata allocation with largest-remainder rounding is applied only to the rationed side.

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
| N (degree) | 2048 | 128 max price levels with SLOT_WIDTH=16 (demo uses 64) |
| t (plaintext mod) | 12289 | Must exceed max(z_buy, z_sell) — not aggregate quantity |
| Moduli | 6 × 62-bit | Sufficient for rotations and masking |
| Price levels | 64 | Discrete price grid size |

## Threshold parameters

| Parameter | Value | Notes |
|-----------|-------|-------|
| Committee size (n) | 3 | Total number of committee members |
| Threshold (t) | 1 | Reconstruction requires 2 parties |
| Smudging λ | 80 bits | Statistical security for noise flooding |
