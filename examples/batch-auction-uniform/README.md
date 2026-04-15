# Uniform-Price Batch Auction (Threshold FHE Demand Curve Demo)

A sealed-bid **uniform-price** batch auction where bidders submit encrypted (quantity, price) pairs under threshold BFV fully-homomorphic encryption. A **2-of-3 committee** jointly generates the encryption key (DKG), aggregates the demand curve homomorphically, and threshold-decrypts only the clearing price and per-bidder allocations — without ever revealing individual bids.

## Quick start

```bash
cargo run --bin demo --release
```

This generates 10 random bids, runs the full threshold FHE pipeline, and asserts the results against a plaintext shadow.

## How it works

### 1. Committee DKG (distributed key generation)

Three committee members run a distributed key generation protocol — **no trusted dealer**.

Each member:
1. Samples a fresh BFV secret key.
2. Computes a **public key share** from their secret key and a shared common random polynomial (CRP).
3. **Shamir-splits** their secret key into shares for distribution to all members.

The public key shares are aggregated into a single **joint public key**. Bidders encrypt to this key. No single committee member knows the corresponding full secret key.

### 2. Encoding: SIMD bit-decomposed demand vectors

Unlike bit-plane encoding which bit-decomposes prices, this demo encodes
each bid as a **cumulative demand ciphertext** built from a plaintext SIMD
step function. For a public price ladder
of $P=64$ levels, each price level uses `SLOT_WIDTH = 16` consecutive
SIMD slots. A bidder with bid $(q_i, price_i)$ bit-decomposes
their quantity $q_i$ across the 16 slots of each level $p$ where
$price\_ladder[p] \le price_i$.

This SIMD bit-decomposed step function is computed in plaintext by the
bidder using `Encoding::simd()`. Each bidder then encrypts the resulting
plaintext vector into a **single BFV ciphertext**. With $N=2048$ and $W=16$, the
scheme supports up to 128 price levels. The encoding is computed entirely
in plaintext on the bidder's device before encryption — the committee never
sees the plaintext demand vector.

### 3. Accumulation: aggregate demand (depth 0)

The aggregator sums all bidder ciphertexts. Because addition is linear
under BFV, the result is a ciphertext where each 16-slot SIMD block
contains the bitwise sum of demanded quantities at that price level.
Summing bit-positions independently avoids carry propagation during FHE.

Total multiplicative depth: **0**. The demand curve is computed using only
homomorphic additions, requiring no rotations or relinearizations for the
core accumulation.

### 4. Threshold decryption (2-of-3)

Any 2 of the 3 committee members can jointly decrypt ciphertexts:

1. Each participating member generates **smudging noise** (see below) and
   computes a **decryption share**.
2. The shares are combined via **Shamir reconstruction** to recover the
   plaintext.

The committee first decrypts the aggregate demand ciphertext to find the
clearing price, then decrypts masked per-bidder slot blocks to determine
allocations.

### 5. Clearing price discovery

The decrypted aggregate demand curve is reconstructed from the
bit-summed SIMD slot blocks and searched in plaintext from highest price
to lowest. The **clearing price $P^*$** is the highest price level where
total demand meets or exceeds the public supply.
 If total demand is less than supply even at the lowest price, the auction clears at the lowest level (undersubscribed).

### 6. Allocation: strict and marginal

Bidders are allocated based on their price relative to $P^*$:
- **Strict winners** ($price_i > P^*$): Receive their full requested quantity.
- **Losers** ($price_i < P^*$): Receive zero allocation.
- **Marginal bidders** ($price_i = P^*$): Receive a pro-rata share of the remaining supply.

The marginal allocation uses the **largest-remainder method** (Hamilton's method) to ensure integer fills sum exactly to the supply. Ties in fractional remainders are broken deterministically by the bidder's SIMD slot block index.

## What is revealed vs. what stays hidden

| Data | Revealed to committee? | When? | Why? |
|------|----------------------|-------|------|
| Aggregate demand curve (64 price levels) | ✅ Yes | After threshold decryption of summed ciphertext | Needed to find clearing price |
| Individual bidder's full demand vector | ❌ Not in the intended flow | Never directly in the demo flow | The committee mask-extracts only the clearing-level slot blocks before decryption |
| Bidder's quantity at clearing price | ✅ Yes (per-bidder) | During allocation | Needed for pro-rata calculation |
| Bidder's quantity above clearing price | ✅ Yes (per-bidder) | During allocation | Needed to identify strict winners |
| Bidder's exact bid price | ❌ Not generally | Sometimes inferable at the margin | Marginal bidders are known to be exactly at the public clearing price |
| Bidder's quantity at non-clearing levels | ❌ Not in the intended flow | Never directly in the demo flow | These SIMD slots are zeroed by mask-multiply before the demo's selective decryption step |
| Any individual's raw bid (qty, price) pair | ❌ Not as a direct plaintext order book | Never directly in the demo flow | The demo reveals only the aggregate curve plus selected per-bidder slot values needed for allocation |

### Ciphertext lifecycle

1. **Encryption**: Bidder encodes a 2048-slot SIMD plaintext (64 levels × 16 bits), encrypts under joint public key → 1 BFV ciphertext per bidder.
2. **Accumulation**: All ciphertexts are summed homomorphically (depth 0) → 1 aggregate ciphertext.
3. **Aggregate decryption**: 2-of-3 committee threshold-decrypts the aggregate → plaintext demand curve. Smudging noise (λ=80 bits) protects the secret key.
4. **Per-bidder decryption**: In the intended demo flow, the committee threshold-decrypts only the SIMD slot blocks at the clearing price and one level above. It applies a plaintext mask with 1s at the target SIMD slot blocks using ct×pt slot-wise multiplication, then threshold-decrypts the masked ciphertext so non-target slots are zeroed before this selective decryption step.
5. **Allocation**: Clearing price, strict-winner quantities, and marginal pro-rata shares are computed in plaintext from the decrypted slot values.

## Comparison with Vickrey demo

| Feature | Vickrey Demo | Uniform-Price Demo |
|---------|--------------|-------------------|
| Ciphertexts per bidder | 64 (bit-planes) | 1 (demand vector) |
| Multiplicative depth | 1 (ct × ct) | 0 (ct×pt masked extraction) |
| Core rotations | Required (reduce-tree) | None for core computation (SIMD slot blocks) |
| Privacy | Second price only | Clearing price + allocations |

## Production considerations

### Distributed evaluation keys

While the core accumulation requires no rotations, the committee still generates Galois and relinearization keys using the repo's **distributed eval-key MPC** flow for consistency with the broader threshold-BFV stack. The masked extraction path in this demo now uses a plaintext SIMD mask via ct×pt multiplication, so it does not require relinearization.

### Trust model

This demo assumes the decrypting 2-of-3 committee follows the protocol and only decrypts the masked ciphertexts authorized by the auction flow. The mask-multiply step narrows what an honest committee learns, but it is not cryptographic access control against a colluding threshold quorum. In production, this would typically be paired with governance, auditability, and economic penalties such as slashing for unauthorized decryptions.

### Smudging noise

Every BFV decryption leaks information about the secret key through the noise term. To prevent this, each decryption share includes **smudging noise** — a random term ($\lambda = 80$ bits) that drowns the key-dependent component, ensuring statistical security for the joint key.

## Project structure

```
src/
├── lib.rs          Core library: params, encoding, accumulation, clearing, allocations
└── bin/
    └── demo.rs     10-bidder demo with 2-of-3 committee and shadow verification
```

## BFV parameters

| Parameter | Value | Notes |
|-----------|-------|-------|
| N (degree) | 2048 | 128 max price levels with SLOT_WIDTH=16 |
| t (plaintext mod) | 12289 | Must exceed number of bidders z |
| Moduli | 6 × 62-bit | Large noise margin for depth-0 additions |
| Price levels | 64 | Discrete ladder within one BFV SIMD ciphertext |

## Threshold parameters

| Parameter | Value | Notes |
|-----------|-------|-------|
| Committee size (n) | 3 | Minimum for threshold semantics |
| Threshold (t) | 1 | Reconstruction requires t+1 = 2 parties |
| Smudging $\lambda$ | 80 bits | Statistical security for noise flooding |
