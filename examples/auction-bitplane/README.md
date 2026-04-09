# Bit-Plane Auction (FHE Vickrey Demo)

A sealed-bid **Vickrey (second-price)** auction where bids are encrypted under BFV fully-homomorphic encryption.  The FHE program determines *who* won and *whose* bid sets the price — without ever decrypting the raw bids.

## Quick start

```bash
cargo run --bin demo
```

This generates 10 random bids, runs the full FHE pipeline, and asserts the result against a plaintext shadow.

## How it works

### Encoding: horizontal SIMD bitplanes

Each bidder occupies one SIMD **slot** (ring position) across 64 packed ciphertexts — one per bit of a `u64` bid.  Slot `i` of bitplane `j` holds bit `j` of bidder `i`'s bid (MSB first).

```
            slot 0    slot 1    slot 2    ...
bitplane 0  (MSB)     (MSB)     (MSB)
bitplane 1
  ...
bitplane 63 (LSB)     (LSB)     (LSB)
```

Bidders encrypt their own bitplanes (one ciphertext per bit) and submit them to the accumulator, which simply adds them slot-wise.

### Tally: one multiply per bitplane (depth 1)

For each bitplane `j`:

1. **`ones`** — rotate-and-add the bitplane to count how many bidders have a 1.
2. **`zeros`** = `n_bidders − ones`.
3. **`tally`** = `bitplane × zeros` — one ciphertext × ciphertext multiply.

`tally[j][i]` is non-zero only when bidder `i` has a 1 *and* some opponents have a 0.  The value equals how many opponents have 0 — a measure of "how much bidder `i` is winning this bit."

Total multiplicative depth: **1** (a single ct × ct multiply per bitplane).

### Ranking: lexicographic comparison in plaintext

The tally matrix is decrypted (this reveals only the tally scores, not the bids).  Each bidder's row is compared lexicographically from MSB to LSB.  The highest row is the winner; the second-highest identifies the Vickrey price source.  Ties are broken deterministically by slot index (lower wins).

### Vickrey price recovery

The FHE program returns `(winner_slot, second_slot)`.  In production, a decryption committee would decrypt only `bid_ciphertexts[second_slot]` to learn the price the winner pays.  The demo does this locally and asserts it matches the plaintext expectation.

## Production considerations

### No relinearization needed

Each tally ciphertext is the product of exactly one ct × ct multiplication and is then immediately decrypted — no further homomorphic operations follow.  BFV decryption handles the resulting 3-polynomial ciphertext natively, so we skip relinearization entirely, saving a significant key-generation and computation cost.

### Noise smudging

Every BFV decryption leaks a small amount of information about the secret key through the noise term.  This demo performs 64 tally decryptions plus 1 bid decryption (65 total).  In production, every decryption must be preceded by **noise flooding** — adding a large random noise term that statistically drowns the key-dependent component.  The demo omits smudging for clarity.

## Project structure

```
src/
├── lib.rs          Core library: encoding, encryption, tally, ranking
└── bin/
    └── demo.rs     10-bidder demo with shadow verification
```

## BFV parameters

| Parameter | Value | Notes |
|-----------|-------|-------|
| N (degree) | 2048 | = max bidders (one SIMD slot each) |
| t (plaintext mod) | 12289 | Prime, NTT-friendly |
| Moduli | 6 × 62-bit | Noise budget for 1 multiply + rotations |
| Bid size | 64 bits | Full `u64` range |
