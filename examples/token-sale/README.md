# Capped Token Sale (Fair Launch)

A sealed-bid **capped token sale** where bidders submit encrypted (quantity, price) pairs under threshold BFV fully-homomorphic encryption. A **2-of-3 committee** jointly determines the clearing price and per-bidder lot allocations while preserving the privacy of individual bids and un-clamped quantities. The protocol enforces a **per-bidder cap** and uses **lot-unit encoding** to ensure a fair distribution across all participants.

## Quick start

```bash
cargo run --bin demo --release
```

This generates 10 random bids (including some exceeding the cap), runs the threshold FHE pipeline, and asserts the result against a plaintext shadow.

## How it works

### 1. Committee DKG
Three committee members run a distributed key generation protocol to produce a **joint public key** without a trusted dealer. Each member samples a BFV secret key, publishes a public share from a common random polynomial (CRP), and distributes Shamir-shares of their secret key. Bidders encrypt exclusively to the aggregated joint public key.

### 2. Encoding: capped cumulative demand vectors
Bidders specify their demand in discrete **lots** (e.g., 1 lot = 100 tokens). Fairness is enforced by a public cap **K** via client-side clamping: `clamped_qty = min(requested_qty, K)`. The encoder uses **multi-coefficient polynomial encoding** (`Encoding::poly()`), where each price level spans `SLOT_WIDTH=16` consecutive coefficients. The `clamped_qty` is bit-decomposed across these 16 coefficients. This clamping is enforced client-side at encoding time, which in production would be verified by **ZK input validation** to prevent whales from bypassing the limit.

### 3. Accumulation: zero-depth sum
The aggregator sums the encrypted demand vectors coefficient-wise. Because BFV addition is linear, this produces an encrypted aggregate demand curve with **zero multiplicative depth**. The plaintext range is constrained by the bidder count `z`, where the count at each bit position must not overflow the BFV plaintext modulus `t = 12289` (i.e., `t > z`). This allows for massive aggregation without overflow.

### 4. Threshold decryption and price discovery
The committee threshold-decrypts the aggregate demand curve using their secret-key shares and **smudging noise** for statistical security. They perform a plaintext search to find the **clearing price P***: the highest price level where total demand meets or exceeds the `total_supply_lots`.

### 5. Allocation and rounding
Per-bidder lot allocations are determined based on the clearing price:
- **Strict winners** (price > P*) receive their full requested (clamped) lots.
- **Losers** (price < P*) receive zero.
- **Marginal bidders** (price == P*) receive a pro-rata share of remaining lots, resolved using **largest-remainder rounding** to maintain discrete lot units.

### 6. Settlement
The final settlement logic computes the payment and refund for each bidder:
- **Payment**: `clearing_price × allocated_lots`.
- **Refund**: `collateral - payment`, where collateral was initially locked as `max_price × clamped_qty`.

## Production considerations

### Distributed evaluation keys
While this demo uses a zero-depth accumulation circuit, any additional rotations or relinearizations would use the repo's **distributed eval-key MPC** flow. This ensures the joint secret key is never reconstructed, even when generating Galois or relinearization keys.

### Smudging noise and ZK validation
To prevent key leakage, every threshold decryption share includes **smudging noise** ($\lambda = 80$ bits). Furthermore, the per-bidder cap $K$ and bid integrity are enforced by the same ZK proof infrastructure used in the Vickrey auction demo (C8-C10 circuits) to ensure bidders follow the encoding rules.

## Project structure

```
src/
├── lib.rs          Core library: SaleConfig, encoding, settlement, and rounding
└── bin/
    └── demo.rs     10-bidder demo with clamping verification and shadow verification
```

## BFV parameters

| Parameter | Value | Notes |
|-----------|-------|-------|
| N (degree) | 2048 | 128 max price levels with SLOT_WIDTH=16 (demo uses 64) |
| t (plaintext mod) | 12289 | Must exceed bidder count, not aggregate demand |
| Moduli | 6 × 62-bit | Large budget for depth 0 operations |
| Price levels | 64 | Discrete steps in the price ladder |

## Threshold parameters

| Parameter | Value | Notes |
|-----------|-------|-------|
| Committee size (n) | 3 | 2-of-3 threshold setup |
| Threshold (t) | 1 | Requires 2 shares to reconstruct |
| Smudging λ | 80 bits | Statistical security for decryption |

## Sale parameters

| Parameter | Value | Notes |
|-----------|-------|-------|
| Lot size | 100 | Tokens per discrete lot |
| Cap K | 500 | Max lots per bidder (clamped) |
| Total supply | 2000 | Total lots available in the sale |
