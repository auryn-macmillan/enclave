# Uniswap CCA (Threshold FHE Sealed-Bid Demo)

A sealed-bid **Uniswap Continuous Clearing Auction (CCA)** replacement where bidders submit encrypted (quantity, price) pairs under threshold BFV fully-homomorphic encryption. A **2-of-3 committee** jointly generates the encryption key (DKG), aggregates the demand curve homomorphically, and threshold-decrypts only a small aggregate witness plus the bidder-level buckets needed for allocations — keeping individual bid parameters private until settlement.

## Quick start

```bash
cargo run --bin demo --release
```

This generates 10 random bids, runs the full threshold FHE pipeline, and checks the result against an internal plaintext shadow.

## How it works

### 1. Committee DKG (distributed key generation)

Three committee members run a distributed key generation protocol — **no trusted dealer**.

Each member:
1. Samples a fresh BFV secret key.
2. Computes a **public key share** from their secret key and a shared common random polynomial (CRP).
3. **Shamir-splits** their secret key into shares for distribution to all members.

The public key shares are aggregated into a single **joint public key**. Bidders encrypt to this key. No single committee member knows the corresponding full secret key.

### 2. Encoding: SIMD bit-decomposed demand vectors

This example encodes each bid as a **cumulative demand ciphertext** built from a plaintext SIMD step function. For a public price ladder of $P=512$ levels, each price level uses `SLOT_WIDTH = 16` consecutive SIMD slots. A bidder with bid $(q_i, price_i)$ bit-decomposes their quantity $q_i$ across the 16 slots of each level $p$ where $price\_ladder[p] \le price_i$.

This SIMD bit-decomposed step function is computed in plaintext by the bidder using `Encoding::simd()`. Each bidder then encrypts the resulting plaintext vector into a **single BFV ciphertext**. With $N=8192$ and $W=16$, the scheme supports up to 512 price levels. The encoding is computed entirely in plaintext on the bidder's device before encryption — the committee never sees the plaintext demand vector.

### 3. Accumulation: aggregate demand (depth 0)

The aggregator sums all bidder ciphertexts. Because addition is linear under BFV, the result is a ciphertext where each 16-slot SIMD block contains the bitwise sum of demanded quantities at that price level. Summing bit-positions independently avoids carry propagation during FHE.

Total multiplicative depth: **0**. The demand curve is computed using only homomorphic additions, requiring no rotations or relinearizations for the core accumulation.

### 4. Threshold decryption (2-of-3)

Any 2 of the 3 committee members can jointly decrypt ciphertexts:

1. Each participating member generates **smudging noise** (see below) and computes a **decryption share**.
2. The shares are combined via **Shamir reconstruction** to recover the plaintext.

The committee first probes the aggregate demand ciphertext at a small set of price buckets to derive the clearing witness, then decrypts masked per-bidder slot blocks only when those reveals are needed for allocation.

### 5. Clearing price discovery

The committee uses selective aggregate bucket decryptions (**binary search**) to find the highest price level where total demand meets or exceeds the public supply. The resulting aggregate witness is:

- `k`: clearing index
- `D[k]`: aggregate demand at the clearing bucket
- `D[k+1]`: aggregate demand strictly above clearing (or 0 at the top)
- undersubscribed flag when `k = 0` and `D[0] < supply`

The **clearing price $P^*$** is `price_ladder[k]`. If total demand is less than supply even at the lowest price, the auction clears at the lowest level (undersubscribed).

### 6. Allocation: strict and marginal

Bidders are allocated based on their price relative to $P^*$:
- **Strict winners** ($price_i > P^*$): Receive their full requested quantity.
- **Losers** ($price_i < P^*$): Receive zero allocation.
- **Marginal bidders** ($price_i = P^*$): Receive a pro-rata share of the remaining supply.

The reveal policy is gated by the aggregate witness:

- **Undersubscribed / no strict-demand easy cases**: decrypt only each bidder's bucket at `k`.
- **General case**: decrypt each bidder's bucket at `k+1` first; only bidders with zero demand above clearing are still ambiguous, so only those bidders get an additional reveal at `k`.

The marginal allocation uses the **largest-remainder method** to ensure integer fills sum exactly to the supply. Ties in fractional remainders are broken deterministically by the bidder's index.

## What is revealed vs. what stays hidden

| Data | Status | Why? |
|------|--------|------|
| Clearing price | Revealed | Required for onchain settlement |
| Aggregate demand at clearing | Revealed | Needed to verify clearing condition |
| Per-bidder allocation | Revealed | Required to distribute tokens |
| Individual max price | Hidden | Never decrypted unless bidder is marginal |
| Individual budget | Hidden | Only total allocation is revealed |
| Demand at non-clearing levels | Hidden | Zeroed by plaintext masks before decryption |

### Ciphertext lifecycle

1. **Encryption**: Bidder encodes an 8192-slot SIMD plaintext (512 levels × 16 bits), encrypts under joint public key → 1 BFV ciphertext per bidder.
2. **Accumulation**: All ciphertexts are summed homomorphically (depth 0) → 1 aggregate ciphertext.
3. **Aggregate witness derivation**: 2-of-3 committee threshold-decrypts only selected aggregate buckets, using binary search to identify `k` and then revealing `D[k]` and `D[k+1]`. Smudging noise (λ=80 bits) protects the secret key.
4. **Per-bidder gated decryption**: The committee applies plaintext masks with 1s at bucket `k` or `k+1` using ct×pt slot-wise multiplication, then threshold-decrypts only those masked ciphertexts authorized by the witness-driven settlement flow.
5. **Allocation**: Clearing price, strict-winner quantities, and marginal pro-rata shares are computed in plaintext from the witness and the gated bidder reveals.

## Comparison with uniform-price batch auction

| Feature | Uniform-Price Auction | Uniswap CCA |
|---------|-----------------------|-------------|
| N (degree) | 2048 | 8192 |
| t (plaintext mod) | 12289 | 65537 |
| Price levels | 64 | 512 |
| Clearing method | Full curve decrypt | Binary search selective reveals |
| Semantics | Generic batch auction | Token-launch CCA |
| Lifecycle bridge | Standalone | Graduates to Uniswap v4 hook |

## Production considerations

### Distributed eval keys

While the core accumulation requires no rotations, the committee still generates Galois and relinearization keys using the repo's **distributed eval-key MPC** flow for consistency with the broader threshold-BFV stack. The masked extraction path uses a plaintext SIMD mask via ct×pt multiplication, requiring no relinearization but utilizing the 11 rotations of the eval-key for other potential advanced operations.

### Trust model

This demo assumes the decrypting 2-of-3 committee follows the protocol and only decrypts the masked ciphertexts authorized by the auction flow. The mask-multiply step narrows what an honest committee learns, but it is not cryptographic access control against a colluding threshold quorum. In production, this is paired with governance and ZK proofs of bid validity verified via onchain validation hooks.

### Smudging noise

Every BFV decryption leaks information about the secret key through the noise term. To prevent this, each decryption share includes **smudging noise** — a random term ($\lambda = 80$ bits) that drowns the key-dependent component, ensuring statistical security for the joint key.

### Lifecycle bridge to v4 hook

Tokens launched via this CCA graduate to a Uniswap v4 pool. The `LiquidityLauncher` seeds the pool at the final discovered clearing price. Ongoing trading can then transition to the encrypted Uniswap v4 hook, utilizing the same committee infrastructure for consistent privacy. Reference `examples/uniswap-v4-hook/` for the post-graduation environment.

## Project structure

```
src/
├── lib.rs          Core library: params, encoding, accumulation, clearing, allocations
└── bin/
    └── demo.rs     10-bidder demo (Alice through Judy) with shadow verification
```

## BFV parameters

| Parameter | Value | Notes |
|-----------|-------|-------|
| N (degree) | 8192 | 512 max price levels with SLOT_WIDTH=16 |
| t (plaintext mod) | 65537 | Fermat prime, exceeds number of bidders |
| Moduli | 3 × 62-bit | Sufficient noise margin for depth-0 aggregation |
| Price levels | 512 | Discrete ladder within one BFV SIMD ciphertext |

## Threshold parameters

| Parameter | Value | Notes |
|-----------|-------|-------|
| Committee size (n) | 3 | Minimum for 2-of-3 threshold semantics |
| Threshold (t) | 1 | Reconstruction requires t+1 = 2 parties |
| Smudging $\lambda$ | 80 bits | Statistical security for noise flooding |
