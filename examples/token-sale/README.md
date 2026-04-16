# Capped Token Sale (Fair Launch)

A sealed-bid **capped token sale** where bidders submit encrypted (quantity, price) pairs under threshold BFV fully-homomorphic encryption. A **2-of-3 committee** jointly determines the clearing price and per-bidder lot allocations while preserving the privacy of unclamped quantities. The demo now follows an **aggregate-first, bidder-second** transcript: it derives a small aggregate witness first, then decrypts bidder-level buckets only when settlement actually needs them. The demo uses **client-side clamping** with lot-unit encoding; production deployments would add ZK input validation for cap compliance.

## Quick start

```bash
cargo run --bin demo --release
```

This runs the full threshold FHE pipeline on a fixed demo batch, including over-cap requests handled by client-side clamping, and asserts the result against a plaintext shadow without printing raw bids.

## How it works

### 1. Committee DKG
Three committee members run a distributed key generation protocol to produce a **joint public key** without a trusted dealer. Each member samples a BFV secret key, publishes a public share from a common random polynomial (CRP), and distributes Shamir-shares of their secret key. Bidders encrypt exclusively to the aggregated joint public key.

### 2. Encoding: capped cumulative demand vectors
Bidders specify their demand in discrete **lots** (e.g., 1 lot = 100 tokens). Fairness is enforced by a public cap **K** via client-side clamping: `clamped_qty = min(requested_qty, K)`. The encoder uses **SIMD bit-decomposed encoding** (`Encoding::simd()`), where each price level spans `SLOT_WIDTH=16` consecutive SIMD slots. The `clamped_qty` is bit-decomposed across these 16 SIMD slots. This clamping is enforced client-side at encoding time, which in production would be verified by **ZK input validation** to prevent whales from bypassing the limit.

### 3. Accumulation: zero-depth sum
The aggregator sums the encrypted demand vectors slot-wise. Because BFV addition is linear, this produces an encrypted aggregate demand curve with **zero multiplicative depth**. The plaintext range is constrained by the per-bit slot count: under the current centered-zero decoder, each bit-position count must stay comfortably below `t/2` for `t = 12289`. In this demo, that bound is far above the bidder count.

### 4. Threshold decryption and aggregate-first price discovery
The committee no longer decrypts the full aggregate demand curve by default. Instead, it applies a plaintext SIMD mask to the **aggregate ciphertext** and threshold-decrypts only the aggregate bucket currently needed by the clearing search. Because cumulative demand is monotone across the public ladder, the committee can search for the **clearing price P*** using only these selectively revealed aggregate buckets.

Once the clearing index `k` is known, the committee derives a minimal aggregate witness:
- `D[k]`: aggregate capped demand at clearing
- `D[k+1]`: aggregate capped demand one ladder step above clearing (or 0 at the top)

These two values are sufficient for the allocation formulas.

### 5. Allocation and rounding
Per-bidder lot allocations are determined based on the clearing price:
- **Strict winners** (price > P*) receive their full requested (clamped) lots.
- **Losers** (price < P*) receive zero.
- **Marginal bidders** (price == P*) receive a pro-rata share of remaining lots, resolved using **largest-remainder rounding** to maintain discrete lot units.

Under SIMD encoding, the committee applies a plaintext SIMD mask via ct×pt slot-wise multiplication to isolate target SIMD slot blocks before threshold decryption. The sale semantics, pro-rata rule, payment formula, refund formula, and cap behavior are unchanged.

### 6. Aggregate-first bidder reveal
The aggregate witness gates bidder-level decryptions:
- The committee first decrypts each bidder's `k+1` bucket only, which identifies strict winners.
- If a bidder has nonzero demand at `k+1`, that already determines their strict fill; the committee does **not** also decrypt that bidder's `k` bucket by default.
- Only bidders with zero strict demand are candidates for marginal fill, so only those bidders have their `k` bucket decrypted.

This means the demo no longer decrypts `{k, k+1}` for every bidder unconditionally.

## What is revealed vs. what stays hidden

| Data | Revealed? | When? | Why? |
|------|-----------|-------|------|
| Aggregate buckets touched by clearing search | ✅ Yes | During selective threshold decryption of summed ciphertext | Needed to find clearing price |
| Final aggregate witness `D[k], D[k+1]` | ✅ Yes | After clearing is found | Needed for strict vs marginal allocation |
| Bidder's capped lots at clearing price | ✅ Yes | During allocation | Needed for pro-rata at marginal |
| Bidder's capped lots above clearing price | ✅ Yes | During allocation | Identifies strict winners |
| Bidder's unclamped (raw) quantity | ❌ No | Never | Clamped client-side before encryption; never enters a ciphertext |
| Bidder's full 64-level demand vector | ❌ Not in the intended flow | Never directly in the demo flow | Only targeted SIMD slot blocks at clearing and above are selectively decrypted |
| Bidder's exact max price | ❌ Not generally | Sometimes inferable at the margin | Marginal bidders are known to be exactly at the public clearing price |
| Lot counts at non-clearing levels | ❌ Not in the intended flow | Never directly in the demo flow | Non-target levels are zeroed by mask-multiply before the demo's selective decryption step |

### Ciphertext lifecycle

1. **Client-side clamping**: Bidder clamps `min(requested, cap_K)` before encoding. Unclamped quantity never enters FHE.
2. **Encryption**: 2048-slot SIMD plaintext (64 levels × 16 bits) encrypted under joint public key → 1 ciphertext per bidder.
3. **Accumulation**: Homomorphic sum (depth 0) → 1 aggregate ciphertext.
4. **Aggregate-first decryption**: 2-of-3 threshold decrypt with 80-bit smudging → only the aggregate buckets touched by the clearing search, then the final witness `D[k], D[k+1]`.
5. **Gated bidder decryption**: Committee first decrypts bidder bucket `k+1`; bidder bucket `k` is decrypted only for bidders that remain marginal candidates.
6. **Settlement**: Allocations, payments, and refunds computed in plaintext from decrypted slot values.

### 6. Settlement
The final settlement logic computes the payment and refund for each bidder:
- **Payment**: `clearing_price × allocated_lots`.
- **Refund**: `collateral - payment`, where collateral was initially locked as `max_price × clamped_qty`.

## Production considerations

### Distributed evaluation keys
While this demo uses a zero-depth accumulation circuit, any additional rotations or relinearizations would use the repo's **distributed eval-key MPC** flow. This ensures the joint secret key is never reconstructed, even when generating Galois or relinearization keys.

### Smudging noise and ZK validation
To prevent key leakage, every threshold decryption share includes **smudging noise** ($\lambda = 80$ bits). In this demo, the per-bidder cap $K$ is enforced by client-side clamping before encryption. A production deployment would pair this with ZK input validation so bidders can prove that the encrypted demand vector respects the public cap without revealing the unclamped request.

### Trust model

This demo assumes the decrypting 2-of-3 committee follows the protocol and only decrypts the masked ciphertexts authorized by settlement. The aggregate-first transcript narrows what an honest committee learns, but it is not cryptographic access control against a colluding threshold quorum.

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
| t (plaintext mod) | 12289 | Under the current decoder, per-bit slot counts must stay comfortably below `t/2` |
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
| Total supply | 1600 | Total lots available in the sale |
