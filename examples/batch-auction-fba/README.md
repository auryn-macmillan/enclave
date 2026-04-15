# Frequent Batch Auction (Threshold FHE Multi-Round Demo)

A periodic **Frequent Batch Auction (FBA)** where orders accumulate in encrypted form and match simultaneously at the end of each discrete time window. A **2-of-3 committee** jointly determines the clearing price and allocations via threshold BFV, using a hybrid carry-forward design where orders persist across multiple epochs without further bidder interaction.

## Quick start

```bash
cargo run --bin demo --release
```

This runs a 3-round simulation with 10 bidders, including order carry-forward and cancellation, asserting all FHE results against a plaintext shadow.

## How it works

### 1. Committee DKG (distributed key generation)

Three committee members run a distributed key generation protocol to create a **joint public key** without a trusted dealer. Each member samples a secret key, computes a public key share, and Shamir-splits their secret for distribution. Bidders encrypt only once to the joint key; no single member can decrypt individual orders on their own.

### 2. Encoding: SIMD bit-decomposed demand vectors

Bidders encode their `(quantity, price)` pair using a high-throughput **SIMD bit-decomposed encoding** (`Encoding::simd()`). Each price level spans `SLOT_WIDTH = 16` SIMD slots, where each SIMD slot holds one bit of the quantity's binary representation. This allows for massive aggregation while maintaining a constant multiplicative depth of zero in the main FBA pipeline.

### 3. Aggregation and clearing

The aggregator sums all active ciphertexts into an **aggregate demand curve**. Because each SIMD slot represents a bit-count across all bidders, the committee can threshold-decrypt this aggregate and decode the total demand at every price level using `decode_demand_curve()`. The clearing price $P^*$ is the highest price where total demand meets or exceeds supply.

### 4. Order classification and allocation

Using the public clearing index $k$, the committee classifies each order from its **public order-price metadata**:
1. **Strict winners** (price > $P^*$): Fully filled. The demo uses the public `order.qty` metadata directly for allocation reporting because a full fill is already implied by `price > P^*`; no participant-level threshold decryption is needed.
2. **Strict losers** (price < $P^*$): Unfilled. Ciphertext is carried forward untouched with zero per-order information revealed.
3. **Marginal** (price = $P^*$): Partially filled. Committee threshold-decrypts the marginal quantity SIMD slot block, computes pro-rata in plaintext, and re-encrypts the residual.

### 5. Multi-round carry-forward

FBA uses **epoch-based priority** where earlier-round orders fill first at the marginal price. The committee re-encrypts marginal residuals for the next epoch's book using `encrypt_residual`. Bidders never interact after their initial submission, enabling a "submit once, match eventually" workflow.

## What is revealed vs. what stays hidden

| Data | Revealed? | When? | Why? |
|------|-----------|-------|------|
| Aggregate demand curve (per round) | ✅ Yes | Each round, after threshold decryption | Needed to find clearing price |
| Strict winner's quantity | ✅ Yes (from public metadata) | During allocation | Full fill is already implied by public `price > P^*`, so the demo reuses public `order.qty` |
| Marginal bidder's quantity at clearing level | ✅ Yes | During allocation | Needed for pro-rata split |
| Strict loser's quantity | ❌ Not in the intended flow | Never directly in the demo flow | Ciphertext carried forward untouched |
| Strict loser's price | ✅ Yes | Submission time | This demo stores order price as public metadata for classification |
| Any bidder's full 64-level demand vector | ❌ Not in the intended flow | Never directly in the demo flow | The demo selectively decrypts only targeted slot blocks |
| Residual quantities (re-encrypted) | ❌ No | Never directly | Committee computes residual = qty - allocation in plaintext, re-encrypts under joint public key |
| Individual bid prices | ✅ Yes | Submission time | This demo keeps order price metadata public so the committee can classify orders relative to clearing |

### Ciphertext lifecycle (per order)

1. **Submission**: Bidder encodes a 2048-slot SIMD plaintext (64 levels × 16 bits), encrypts under joint public key → 1 BFV ciphertext.
2. **Aggregation**: Per-round sum of all active ciphertexts (depth 0) → 1 aggregate ciphertext per round.
3. **Aggregate decryption**: 2-of-3 threshold decrypt with 80-bit smudging noise → plaintext demand curve.
4. **Classification decryption**: Committee uses public order metadata to identify strict winners and losers. Only marginal orders require plaintext SIMD masking plus ct×pt slot-wise multiplication before threshold decryption of the single block at `k`. Losers' ciphertexts are not decrypted in the intended flow, and strict winners need no participant-level quantity decryption.
5. **Carry-forward**: Strict losers' original ciphertexts persist unchanged. Marginal residuals are re-encrypted as fresh ciphertexts. Winners' ciphertexts are dropped.
6. **Cross-round**: Steps 2–5 repeat each epoch with the updated book. Earlier-epoch orders get priority at marginal fills.

## Production considerations

### Distributed evaluation keys

While the core FBA pipeline under SIMD encoding uses pure ciphertext additions and threshold decryption, the repository's distributed eval-key MPC infrastructure remains fully integrated. The only remaining per-order extraction path is the marginal-order branch, which uses a plaintext SIMD mask via ct×pt slot-wise multiplication; the existing distributed eval-key machinery remains available for other mechanisms that may require Galois rotations or relinearization.

### Smudging noise

Threshold decryption shares include **80-bit smudging noise** to protect the secret key from leakage during the multi-round process. Because the main pipeline is dominated by additions, ciphertext noise growth is minimal. The demo now restricts plaintext-mask ct×pt extraction to marginal orders only.

### Trust model

This example does **not** provide hidden order prices: `price` is public metadata used for order classification. It also assumes the decrypting 2-of-3 committee follows the protocol and only decrypts the masked ciphertexts authorized by the auction flow. In production, this would typically be paired with governance, auditability, and economic penalties such as slashing for unauthorized decryptions.

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
| t (plaintext mod) | 12289 | Per-bit slot counts must stay comfortably below `t/2`; in this demo that is far above the bidder count |
| Moduli | 6 × 62-bit | Sufficient for multiple rounds and slow noise growth |
| Price levels | 64 | Discrete ladder 0..63 |

## Threshold parameters

| Parameter | Value | Notes |
|-----------|-------|-------|
| Committee size (n) | 3 | 2-of-3 threshold setup |
| Threshold (t) | 1 | Any 2 members can reconstruct |
| Smudging λ | 80 bits | Statistical security for noise flooding |
