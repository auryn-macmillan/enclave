# Discrete-Ladder Vickrey Auction (Threshold FHE Demo)

A sealed-bid **Vickrey (second-price)** auction where bids are encrypted under threshold BFV fully-homomorphic encryption. A **2-of-3 committee** jointly generates the encryption key (DKG), computes a cumulative occupancy curve and a pair-indicator curve, then makes only the authorized decryptions needed to reveal the second price and identify the winner.

## Quick start

```bash
cargo run --bin demo --release
```

This runs the full threshold FHE pipeline on a fixed demo bid set, prints the progressive public transcript, and asserts the result against a plaintext shadow.

## How it works

### 1. Committee DKG (distributed key generation)

Three committee members run a distributed key generation protocol — no trusted dealer.

Each member:
1. Samples a fresh BFV secret key.
2. Computes a **public key share** from their secret key and a shared common random polynomial (CRP).
3. **Shamir-splits** their secret key into shares for distribution to all members.

The public key shares are aggregated into a single **joint public key**. Bidders encrypt to this key. No single committee member knows the corresponding full secret key.

Each member also aggregates the Shamir shares they received from others into their **secret-key polynomial sum**, used later for threshold decryption.

### 2. Encoding: discrete ladder buckets

Bidders map their willingness to pay onto a public ascending price ladder. Each bidder encrypts **one SIMD ciphertext** with two logical regions:

1. a **cumulative occupancy curve** with value `1` at every price bucket at or below their chosen bucket, and
2. a **submission-order payload** stored only at the bidder's chosen bucket.

This means the auction never needs to decrypt an exact raw bid amount. It works entirely with ladder buckets.

### 3. Aggregate curves

Bidders submit their encrypted ladder vectors to the accumulator, which adds them slot-wise.

This produces an **aggregate cumulative occupancy curve** where bucket `k` contains the number of bidders willing to pay at least price `P_k`.

The demo then performs one extra depth-1 multiplication on that aggregate curve to derive a **pair-indicator curve** whose decrypted buckets are non-zero exactly when at least two bidders are present at-or-above that ladder price.

### 4. Progressive public decryption

The committee uses threshold decryption to reveal only the minimum information needed:

1. **Second-price discovery**: Threshold-decrypt pair-indicator buckets from the top down. The first bucket whose decrypted indicator is non-zero is the **second-price bucket**.
2. **Top bucket discovery**: If the top bucket is not already implied by the second-price bucket, threshold-decrypt cumulative occupancy buckets above the second price until the highest occupied bucket is found. This is an internal control step for the protocol flow; it does not need to be announced as the winner's full bucket price in the public narrative.
3. **Winner identification**:
   - If the second-price bucket is strictly below the top bucket, the committee performs a targeted decryption of each bidder's presence bit at the **next ladder step above the second-price bucket**. This confirms which bidder is strictly above the second price without revealing the winner's exact higher bucket.
   - If the second-price bucket equals the top bucket (a tie at the highest price), the committee decrypts the top bucket's presence and submission-order payloads for bidders in that bucket, then selects the earliest submission.

The winner's exact surplus and all individual bid amounts remain encrypted.

### 5. Privacy guarantees

- **Winner's surplus is protected**: The winner's exact willingness to pay above the revealed bucket is never revealed.
- **Losing bids are protected**: No losing bidder's exact bid is revealed. The public sees only the aggregate occupancy / pair indicators plus the minimum per-bidder bucket data needed to identify the winner.
- **No trusted auctioneer**: Authorized decryptions are public. The committee is not expected to keep authorized outputs secret; instead, the protocol minimizes what is authorized for decryption.

## Production considerations

### Distributed evaluation keys

The demo still generates distributed Galois and relinearization keys using the repo's eval-key MPC flow, ensuring the joint secret key is never reconstructed. The current auction logic uses the relinearization key for the aggregate pair-indicator curve; future variants may also use the Galois keys for more advanced selection flows.

### Smudging noise

Every BFV decryption leaks a small amount of information about the secret key through the noise term. Each decryption share includes **smudging noise** — a large random term (λ = 80 bits of statistical security) that drowns the key-dependent component.

## Project structure

```
src/
├── lib.rs          Core library: params, DKG, ladder encoding, aggregate curves, threshold decryption, winner/price helpers
└── bin/
    └── demo.rs     5-bidder demo with 2-of-3 committee and shadow verification
```

## BFV parameters

| Parameter | Value | Notes |
|-----------|-------|-------|
| N (degree) | 2048 | Enough for 64 ladder buckets × two logical regions × 16 bits |
| t (plaintext mod) | 12289 | Prime, NTT-friendly |
| Moduli | 6 × 62-bit | Noise budget for one depth-1 pair-indicator multiply plus threshold decryption |

## Threshold parameters

| Parameter | Value | Notes |
|-----------|-------|-------|
| Committee size (n) | 3 | Minimum for threshold semantics |
| Threshold (t) | 1 | Reconstruction requires t+1 = 2 parties |
| Smudging λ | 80 bits | Statistical security for noise flooding |
