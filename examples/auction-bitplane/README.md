# Bit-Plane Auction (Threshold FHE Vickrey Demo)

A sealed-bid **Vickrey (second-price)** auction where bids are encrypted under threshold BFV fully-homomorphic encryption.  A **2-of-3 committee** jointly generates the encryption key (DKG), computes the tally homomorphically, and threshold-decrypts only the ranking and second price — without ever decrypting the raw bids.

## Quick start

```bash
cargo run --bin demo --release
```

This generates 10 random bids, runs the full threshold FHE pipeline, and asserts the result against a plaintext shadow.

## How it works

### 1. Committee DKG (distributed key generation)

Three committee members run a distributed key generation protocol — **no trusted dealer**.

Each member:
1. Samples a fresh BFV secret key.
2. Computes a **public key share** from their secret key and a shared common random polynomial (CRP).
3. **Shamir-splits** their secret key into shares for distribution to all members.

The public key shares are aggregated into a single **joint public key**.  Bidders encrypt to this key.  No single committee member knows the corresponding full secret key.

Each member also aggregates the Shamir shares they received from others into their **secret-key polynomial sum**, used later for threshold decryption.

### 2. Encoding: BFV row-halves

Each bidder occupies one SIMD **slot** (ring position) across 64 packed ciphertexts — one per bit of a `u64` bid.  Slot `i` of bitplane `j` holds bit `j` of bidder `i`'s bid (MSB first).

With degree $N=2048$, BFV SIMD slots are organized as two rows of $N/2 = 1024$ slots each.  Rotations operate cyclically within each row.  To sum across all 2048 slots, the tally implementation performs $log_2(1024)$ column rotations followed by a row swap.

```
            slot 0    slot 1    ...    slot 1023
row 0       bidder 0  bidder 1         bidder 1023
row 1       bidder 1024 ...            bidder 2047
```

Bidders encrypt their own bitplanes with the joint public key and submit them to the accumulator, which adds them slot-wise.

### 3. Tally: one multiply per bitplane (depth 1)

For each bitplane `j`:

1. **`masked`** = `bitplane × slot_mask` — zero out unused SIMD slots (ct × pt, depth 0).  Without this, accumulated encryption noise in unused slots corrupts the all-slot sum.
2. **`ones`** — rotation-reduce-tree sum of the masked bitplane.
3. **`zeros`** = `n_bidders − ones`.
4. **`tally`** = `bitplane × zeros` — one ct × ct multiply.
5. **Relinearize** — reduce the degree-3 ciphertext back to degree 2 for threshold decryption.

`tally[j][i]` is non-zero only when bidder `i` has a 1 *and* some opponents have a 0.  The value equals how many opponents have 0 — a measure of "how much bidder `i` is winning this bit."

Total multiplicative depth: **1** (a single ct × ct multiply per bitplane).

### 4. Threshold decryption (2-of-3)

Any 2 of the 3 committee members can jointly decrypt ciphertexts:

1. Each participating member generates **smudging noise** (see below) and computes a **decryption share** for each ciphertext.
2. The shares are combined via **Shamir reconstruction** to recover the plaintext.

The committee first threshold-decrypts the 64 tally ciphertexts, then ranks bidders lexicographically.

### 5. Ranking and Vickrey price

The decrypted tally matrix is compared row-by-row (MSB → LSB).  The highest row is the winner; the second-highest identifies the Vickrey price source.  Ties are broken deterministically by slot index (lower wins).

The FHE program **never decrypts raw bids**.  The committee uses the ranking to select which input ciphertext to threshold-decrypt — the second-ranked bidder's bitplanes — to recover the Vickrey price.

## Production considerations

### Eval key shortcut

The rotation reduce-tree requires a Galois (evaluation) key, and relinearization requires a relinearization key.  The `fhe` library can only build these from a full secret key — no multiparty key generation protocol exists in the library.

This demo reconstructs the full secret key *temporarily* from all committee members' raw secret keys, builds both keys, and immediately discards the reconstructed key.  DKG and threshold decryption remain fully distributed.

A production system would need an MPC protocol for Galois and relinearization key generation (e.g. the approach in Mouchet et al., "Multiparty Homomorphic Encryption from Ring-Learning-with-Errors").

### Smudging noise

Every BFV decryption leaks a small amount of information about the secret key through the noise term.  Each decryption share includes **smudging noise** — a large random term (λ = 80 bits of statistical security) that drowns the key-dependent component.

This demo generates smudging noise via `TRBFV::generate_smudging_error` for every threshold decryption.

## Project structure

```
src/
├── lib.rs          Core library: params, DKG, encoding, tally, threshold decryption, ranking
└── bin/
    └── demo.rs     10-bidder demo with 2-of-3 committee and shadow verification
```

## BFV parameters

| Parameter | Value | Notes |
|-----------|-------|-------|
| N (degree) | 2048 | = max bidders (one SIMD slot each) |
| t (plaintext mod) | 12289 | Prime, NTT-friendly |
| Moduli | 6 × 62-bit | Noise budget for 1 multiply + rotations + relinearization |
| Bid size | 64 bits | Full `u64` range |

## Threshold parameters

| Parameter | Value | Notes |
|-----------|-------|-------|
| Committee size (n) | 3 | Minimum for threshold semantics |
| Threshold (t) | 1 | Reconstruction requires t+1 = 2 parties |
| Smudging λ | 80 bits | Statistical security for noise flooding |
