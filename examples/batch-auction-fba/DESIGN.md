# Frequent Batch Auction (FBA) — FHE Circuit Design

> **Milestone**: M2 (see `AGENTS.md`)
> **Status**: Design v2 — hybrid homomorphic carry-forward, implemented
> **Infrastructure**: Threshold BFV (2-of-3 committee), distributed DKG + eval-key MPC

## 1. Problem Statement

A **Frequent Batch Auction (FBA)** extends the uniform-price batch auction (M1)
into discrete time intervals. Orders accumulate in encrypted form during a
submission window, then are matched simultaneously at the end of each batch
epoch.

The FHE program determines the clearing price and allocations for each batch
identically to M1. The innovation lies in the multi-round orchestration:

1. **Batch Epochs**: Discrete rounds (e.g., Round 1, 2, 3) where trades are
   bunched together.
2. **Order Persistence**: Unfilled or partially filled orders automatically
   carry forward to the next epoch.
3. **Cross-Batch Priority**: Orders from earlier epochs take priority over
   same-price orders from later epochs.

**Privacy guarantee**: The aggregate demand curve is decrypted each round to
determine the clearing price. Individual bids of strict losers are never
revealed. Winners and marginal bidders have one SIMD slot block each
threshold-decrypted (the minimum needed for allocation reporting and pro-rata
computation).
Strict losers are handled entirely homomorphically. The bidder never needs
to interact after initial submission.

## 2. Key Insight: Hybrid Homomorphic Carry-Forward

### 2.1 Problem with Naive Carry-Forward

In a naive design, partially filled orders require a new ciphertext encoding
the residual quantity. This forces either:

- The **bidder** to come back online and re-encrypt (breaks "submit once"), or
- The **aggregator** to know individual quantities (breaks privacy).

### 2.2 Solution: Classify and Handle by Category

After clearing at public price index `k`, every order falls into one of three
categories based on its encrypted demand vector:

| Category | Condition | Residual | Homomorphic? |
|----------|-----------|----------|--------------|
| **Strict winner** | price > P* | 0 (fully filled) | ✅ Drop ciphertext (decrypt 1 SIMD slot block for allocation reporting) |
| **Strict loser** | price < P* | original qty (unfilled) | ✅ Keep ciphertext as-is, zero decryptions |
| **Marginal** | price = P* | original − pro_rata_fill | Decrypt 1 SIMD slot block for pro-rata + re-encrypt residual |

Strict losers require **zero per-order information** — the clearing index `k`
is public, and losers are identified from their public price metadata. Only
losers are handled fully homomorphically. Winners and marginals each require
one SIMD slot block decrypted: winners to report their fill quantity, marginals to
compute pro-rata and re-encrypt the residual.

### 2.3 Why Marginal Bidders Cannot Be Fully Homomorphic

Pro-rata allocation at the marginal price requires:
`fill_i = floor(q_i × R / Q_m)` plus largest-remainder tiebreaking.

This involves **per-order integer division**, which BFV cannot express. The
marginal quantities must be decrypted so that the committee (or an MPC among
committee members) can compute exact integer pro-rata fills and re-encrypt
the residuals.

## 3. Encoding Scheme

### 3.1 Price Ladder

Same as M1. A public ascending ladder of `P = 64` discrete price levels.

### 3.2 Cumulative Demand Vector (Submission Encoding)

The implementation uses **SIMD bit-decomposed encoding** (`Encoding::simd()`). Each logical price level spans `SLOT_WIDTH = 16` SIMD slots.

Bidders submit encrypted (quantity, price) pairs. The quantity is bit-decomposed, and each bit is stored in one of the 16 SIMD slots within the block corresponding to the price level. Under SIMD encoding, ciphertext-ciphertext multiplication is Hadamard (slot-wise), so encrypted masks can be applied via ct×ct mask-multiply when privacy-preserving extraction is needed.

With $N=2048$ and `SLOT_WIDTH=16`, the system supports up to 128 price levels (the demo uses 64).

### 3.3 Aggregation Strategy

The FBA aggregates cumulative demand vectors directly via ciphertext addition, exactly like M1. The original design's one-hot / adjacent-difference transform was removed to simplify the pipeline.

Under SIMD encoding, Galois rotations do act as simple slot shifts, so slot-level transforms remain available if needed. Even so, the implementation keeps the direct cumulative aggregation approach because it already achieves the required demand-curve computation at depth 0 without adding rotational complexity.

By aggregating cumulative vectors directly, the system maintains $O(1)$ depth and keeps the homomorphic pipeline simple.

## 4. Carry-Forward Protocol

After clearing at public price index `k` with clearing price `P*`:

### Step 1: Classify orders (public information only)

The clearing index `k` is public. For each active order's ciphertext `V_i`:

- Determine if it is a **Strict Winner**, **Strict Loser**, or **Marginal** based on the public price metadata associated with the order.
- Classification masks (`build_classification_masks`) target the relevant SIMD slot blocks for the clearing price level. Under SIMD encoding, these masks can be applied homomorphically via Hadamard ct×ct mask-multiply when privacy-preserving extraction is desired, while the current flow still uses them to guide targeted threshold decryption.

### Step 2: Handle strict winners

If the order is priced above clearing (`price > P*`), the order is fully
filled. The ciphertext is dropped (no carry-forward needed).

To report the per-order allocation, the committee threshold-decrypts the
bidder's ciphertext and reads the SIMD slot block at the order's price level to learn `q_i`. The allocation for this order is `fill_i = q_i` (full fill).

### Step 3: Handle strict losers

If the order is priced below clearing, allocation is zero. **Keep `V_i`
unchanged** as the carried-forward ciphertext. This requires zero per-order decryptions.

### Step 4: Handle marginal bidders

For orders priced exactly at `P*`:

1. **Threshold-decrypt quantity**: The committee uses `decrypt_demand_slot_qty` to decrypt the bidder's ciphertext and read the SIMD slot block at index `k`, revealing `q_i`.

2. **Compute pro-rata allocation** in plaintext: Using all marginal
   quantities, epoch metadata, and the remaining supply after strict winners
   are filled, compute `allocate_fba(...)` with epoch-based priority.

3. **Compute residual**: `r_i = q_i - fill_i`.

4. **Re-encrypt residual**: The committee encodes the residual quantity `r_i` at the marginal price slot, encrypts it with the joint public key (`encrypt_residual`), and uses this as the carried-forward ciphertext. The bidder is not involved.

5. **Rerandomization**: Add `Enc(0)` to the re-encrypted residual to prevent
   transcript-level linkability.

### Step 5: Assemble next-round book

The next round's ciphertext book consists of:
- Loser ciphertexts (unchanged)
- Marginal residual ciphertexts (committee re-encrypted)
- Newly submitted ciphertexts (from the next epoch's submission window)

## 5. FHE Circuit Analysis

### 5.1 Operations Per Round

| Operation | Type | Depth | Count |
|-----------|------|-------|-------|
| Aggregate cumulative sum | ct+ct | 0 | N-1 additions |
| Threshold decrypt aggregate | decrypt | — | 1 ciphertext |
| Threshold decrypt winners | decrypt | — | Per strict winner |
| Threshold decrypt marginal | decrypt | — | Per marginal order |
| Re-encrypt residual | encrypt | — | Per marginal order |
| Rerandomize carry-forward | ct+ct (Enc(0)) | 0 | Per carried order |

### 5.2 Comparison: v1 (Naive) vs v2 (Implemented)

| Feature | v1 (Naive) | v2 (Implemented) |
|---------|------------|-------------|
| Bidder interaction after submit | Re-encrypt residual each round | None — submit once |
| Per-order decryptions | 2 slots × every order × every round | 1 SIMD slot block × non-loser orders only; losers: 0 |
| Aggregator learns | Individual (qty_at, qty_above) for all | Quantities of winners + marginals only |
| Depth consumed | 0 | 0 |
| Extra FHE ops | None | None (pure additions) |

### 5.3 Parameter Sufficiency

Same as M1. Parameters N=2048, t=12289, 6×62-bit moduli are sufficient.
The plaintext range constraint is `t > z` (number of bidders), as each SIMD slot in the SIMD bit-decomposed encoding represents a bit-count across bidders. Since `12289 > number of bidders`, no carries occur between bit positions during aggregation.

### 5.4 Noise Budget

The pipeline is now primarily composed of ciphertext additions and threshold decryptions, so the noise growth is extremely slow. SIMD encoding also makes depth-1 Hadamard ct×ct mask-multiply available for privacy-preserving extraction if needed, while the main carry-forward flow remains addition-dominated and supports a very large number of rounds before noise becomes a factor.

## 6. Clearing Price Computation

The aggregator sums the cumulative demand vectors to produce an aggregate ciphertext. After threshold decryption, the committee decodes the aggregate demand curve using `decode_demand_curve()`. This recovers the total demand at each price level. The clearing price is the highest price index `k` where `D[k] >= supply`.

## 7. Allocation Computation

### 7.1 Cross-Batch Time Priority

When multiple bidders are at the marginal price `P*`:

1. **Epoch Priority**: Earlier-epoch orders filled first.
2. **Pro-rata within epoch**: Largest-remainder rounding with order-id tiebreak.

### 7.2 Per-Order Quantity Discovery

The committee identifies non-loser orders using public price metadata. It uses `decrypt_demand_slot_qty()` to threshold-decrypt the relevant SIMD slot block for each such order. This reveals the individual quantity `q_i` required for allocation and residual calculation.

## 8. Protocol Flow

```
Round n Window  ──►  Round n Match  ──►  Carry-Forward  ──►  Round n+1 Window
     │                    │                    │                    │
Submit bids          Sum vectors          Classify orders     Submit new bids
(encrypt once)       Decrypt aggregate    Winners: decrypt    (encrypt once)
                     Find clearing k        qty, drop ct
                     Decrypt non-losers   Losers: keep ct
                     Allocate             Marginals: decrypt,
                                            compute residual,
                                            re-encrypt
```

1. **Submission**: Bidders encrypt `(qty, price)` using SIMD bit-decomposed encoding, submit once.
2. **Aggregation**: Sum all active ciphertexts into an aggregate demand curve.
3. **Decryption**: Committee threshold-decrypts the aggregate ciphertext.
4. **Clearing**: Find the clearing price index `k` from the decrypted demand curve.
5. **Classification**: Using public price metadata, classify each order.
6. **Non-loser decryption**: Committee threshold-decrypts winners' and marginals' price-level SIMD slot blocks to learn quantities.
7. **Allocation**: Compute fills using decrypted quantities, epoch priority, and pro-rata logic.
8. **Carry-forward**: Committee re-encrypts marginal residuals. Loser ciphertexts are kept. Winner ciphertexts are dropped.

## 9. Implementation Plan

### Phase 1: Library changes (`src/lib.rs`)

Key implementation details:
- `build_classification_masks(clearing_idx, params)`: Generates SIMD slot-range masks for isolation during decryption or optional Hadamard mask-multiply.
- `decrypt_demand_slot_qty(ct, slot_idx, ...)`: Threshold-decrypts a specific price-level SIMD slot block from a bidder's ciphertext.
- `encrypt_residual(qty, price_idx, ...)`: Re-encrypts a residual quantity into a new SIMD-encoded ciphertext.

The functions `to_one_hot`, `accumulate_one_hot`, and `histogram_to_demand_curve` from the original design were removed as the pipeline was simplified to use direct cumulative aggregation.

### Phase 2: Demo binary (`src/bin/demo.rs`)

The demo implements the homomorphic carry-forward flow:
- Bidders submit once.
- Aggregation uses pure additions of cumulative vectors.
- Committee manages decryption and residual re-encryption.
- Shadow verification ensures correctness.

## 10. Edge Cases

| Case | Handling |
|------|----------|
| All orders are strict winners | No marginal decryption needed. No carry-forward. |
| All orders are strict losers | No decryption beyond aggregate. All ciphertexts carry forward. |
| All orders are marginal | Every order's SIMD slot block at `k` is decrypted. Maximum per-order disclosure. |
| Zero marginal bidders | Clearing price falls between two price levels. No pro-rata needed. |
| Order cancelled after partial fill | Valid; ciphertext removed from book before next aggregation. |

## 11. Privacy Analysis

| Information | Who learns it | When |
|-------------|---------------|------|
| Aggregate demand curve | Committee (2-of-3) | Each round |
| Clearing price and index | Public | Each round |
| Individual quantity (winners) | Committee (2-of-3) | Round where order is filled |
| Individual quantity (marginal bidders) | Committee (2-of-3) | Round where order is marginal |
| Individual quantity (strict losers) | Nobody | Never (until filled or cancelled) |
| Order price level | Public | Submission time |
| Order epoch | Public | Submission time |

## 12. Open Questions

1. **Secret prices**: If order prices should also be secret, classification would require different encoding strategies.
2. **Galois Rotations**: Under SIMD encoding, rotations behave as expected slot shifts. The current FBA pipeline still avoids them for simplicity, but they remain available for other mechanisms that may benefit from slot movement.
