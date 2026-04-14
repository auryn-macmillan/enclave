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

The exchange uses a public grid of 64 discrete price levels. Participants encode their orders using **SIMD bit-decomposed encoding** (`SLOT_WIDTH = 16`, `Encoding::simd()`). Each price level spans 16 SIMD slots, and the quantity is bit-decomposed across these slots:

*   **Buyers** (Demand): Encode a **descending step function**. A buyer with `(quantity, max_price)` bit-decomposes their quantity into the SIMD slot blocks for all price levels where the level is less than or equal to `max_price`.
*   **Sellers** (Supply): Encode an **ascending step function**. A seller with `(quantity, min_price)` bit-decomposes their quantity into the SIMD slot blocks for all price levels where the level is greater than or equal to `min_price`.

This encoding allows for high-throughput aggregation without carries between slots and keeps the circuit at **multiplicative depth 0**.

### 3. Accumulation: Curve Summation

The aggregator maintains two separate encrypted accumulators. It sums all buyer ciphertexts into an aggregate **buy demand curve** and all seller ciphertexts into an aggregate **sell supply curve**. Because BFV addition is native and slot-wise, this accumulation happens at **multiplicative depth 0**.

### 4. Threshold Decryption of Curves

The committee threshold-decrypts both aggregate curves. Since these curves only reveal the total bit-counts at each SIMD slot position across price levels, individual participant quantities and prices stay private.

### 5. Clearing Price Computation

The committee identifies the clearing price by performing a descending scan of the decrypted curves. The clearing price is the highest price level where:
1. Aggregate buy demand is greater than or equal to aggregate sell supply.
2. Aggregate sell supply is greater than zero.

If the curves do not intersect, the clearing price returns `None` and no trades occur.

### 6. Rationing and Allocation

Once the clearing price index `k` is found, the committee determines which side is rationed:
*   If `demand > supply` at the clearing price, buyers are rationed.
*   If `supply > demand`, sellers are rationed.

Under SIMD encoding, ct×ct mask-multiply is possible via Hadamard multiplication. The committee can encrypt a mask with 1s at the target SIMD slots and isolate the relevant SIMD slot blocks at depth 1 before threshold decryption. In this demo, the committee still threshold-decrypts the full ciphertexts of relevant participants and reads the needed SIMD slot blocks directly. Buyers use blocks at price levels `(k, k+1)` to distinguish strict winners from marginal demand. Sellers use blocks at price levels `(k, k-1)` (or just `k` at the lowest price). Pro-rata allocation with largest-remainder rounding is applied only to the rationed side.

## What is revealed vs. what stays hidden

| Data | Revealed? | When? | Why? |
|------|-----------|-------|------|
| Aggregate buy demand curve (64 levels) | ✅ Yes | After threshold decryption | Needed for clearing price intersection |
| Aggregate sell supply curve (64 levels) | ✅ Yes | After threshold decryption | Needed for clearing price intersection |
| Buyer's quantity at clearing level k and k+1 | ✅ Yes | During allocation | Distinguishes strict winners from marginal buyers |
| Seller's quantity at clearing level k and k-1 | ✅ Yes | During allocation | Distinguishes strict sellers from marginal sellers |
| Any participant's full 64-level demand/supply vector | ❌ No | Never | Only 2 adjacent SIMD slot blocks per participant are read |
| Buyer's max price or seller's min price | ❌ No | Never | Only quantities at specific levels are revealed, not reservation prices |
| Quantities at non-adjacent price levels | ❌ No | Never | Not decrypted (zeroed by mask-multiply in production) |

### Ciphertext lifecycle

1. **Encryption**: Buyer encodes descending step function, seller encodes ascending step function — each as a 2048-slot SIMD plaintext (64 levels × 16 bits), encrypted under joint public key → 1 ciphertext per participant.
2. **Accumulation**: Separate Hadamard sums for buy and sell sides (depth 0) → 2 aggregate ciphertexts.
3. **Curve decryption**: 2-of-3 threshold decrypt both aggregates with 80-bit smudging → 2 plaintext curves.
4. **Clearing**: Committee performs descending scan in plaintext to find intersection → clearing price.
5. **Per-participant decryption**: Committee threshold-decrypts each participant's ciphertext and reads only the 2 relevant SIMD slot blocks (at k and k±1). In production, ct×ct mask-multiply (depth 1) would isolate these slots before decryption.
6. **Allocation**: Pro-rata with largest-remainder rounding applied to the rationed side.

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
