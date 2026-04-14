# Frequent Batch Auction (FBA) — FHE Circuit Design

> **Milestone**: M2 (see `AGENTS.md`)
> **Status**: Design v2 — hybrid homomorphic carry-forward
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
revealed. Winners and marginal bidders have one slot each threshold-decrypted
(the minimum needed for allocation reporting and pro-rata computation).
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
| **Strict winner** | price > P* | 0 (fully filled) | ✅ Drop ciphertext (decrypt 1 slot for allocation reporting) |
| **Strict loser** | price < P* | original qty (unfilled) | ✅ Keep ciphertext as-is, zero decryptions |
| **Marginal** | price = P* | original − pro_rata_fill | Decrypt 1 slot for pro-rata + re-encrypt residual |

Strict losers require **zero per-order information** — the clearing index `k`
is public, and losers are identified from their public price metadata. Only
losers are handled fully homomorphically. Winners and marginals each require
one slot decrypted: winners to report their fill quantity, marginals to
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

Same as M1. Bidder `i` encodes `(q_i, price_i)` as a step function vector
`v_i` where `v_i[p] = q_i` for all `price_ladder[p] <= price_i`, and 0
otherwise. This occupies SIMD slots 0..P-1. Remaining slots are zero.

### 3.3 One-Hot Price Vector (Carry-Forward Encoding)

For carry-forward processing, each bidder's step-function ciphertext is
converted to a **one-hot price-quantity vector** via adjacent differencing:

```
B_i[p] = V_i[p] - V_i[p+1]    for p = 0..P-2
B_i[P-1] = V_i[P-1]
```

Result: `B_i` has the bidder's quantity `q_i` at exactly the slot corresponding
to their price, and zero everywhere else. This is computed homomorphically
as a ct − pt operation after extracting `V_i[p+1]` via a column rotation.

**Implementation**: Construct a plaintext mask that is 1 in slots 0..P-2 and 0
elsewhere. Rotate the ciphertext left by 1 slot (column rotation), multiply
by the mask to zero the wraparound, then subtract from the original:

```
rotated = eval_key.rotates_columns_by(&ct, 1)
masked_rotated = rotated × zero_guard_mask     // ct × pt, depth 0
B = ct - masked_rotated                        // ct - ct, depth 0
```

The `zero_guard_mask` has 1 in slots 0..P-2 and 0 in slot P-1 (and all slots
≥ P). This prevents the cyclic column rotation from wrapping slot 1023
(or slot P, which is 0 anyway) into slot 0.

**Depth**: 0 (one ct×pt mask + one ct−ct subtraction). No multiplicative
depth consumed.

### 3.4 Reconstructing Cumulative Form

If needed for the next round's aggregation (since `accumulate_demand` expects
cumulative vectors), the one-hot form can be converted back to cumulative via
a suffix-sum: `V_i[p] = Σ_{j≥p} B_i[j]`. However, this requires `log2(P)`
rotations on a per-bidder ciphertext, which is expensive.

**Preferred approach**: Keep carried-forward ciphertexts in one-hot form.
New submissions are also converted to one-hot before aggregation. The
aggregate one-hot histogram is then converted to a cumulative demand curve
via a single suffix-sum on the aggregate ciphertext (one set of rotations
shared across all bidders), or the committee simply decrypts the histogram
and computes the cumulative sum in plaintext.

**Simplest approach for this demo**: Since the aggregate demand curve is
threshold-decrypted every round anyway, we can aggregate one-hot ciphertexts
directly. The decrypted histogram `H[p]` gives per-price-level total demand.
The cumulative curve is `D[p] = Σ_{j≥p} H[j]`, computed in plaintext after
decryption. This avoids any FHE suffix-sum rotations entirely.

## 4. Carry-Forward Protocol

After clearing at public price index `k` with clearing price `P*`:

### Step 1: Classify orders (public information only)

The clearing index `k` is public. For each active order's ciphertext `V_i`:

- Compute `B_i` (one-hot form) via adjacent differencing (§3.3)
- Apply a **winner mask** `M_w`: 1 in slots k+1..P-1, 0 elsewhere →
  `W_i = B_i × M_w` isolates the strict-winner component
- Apply a **loser mask** `M_l`: 1 in slots 0..k-1, 0 elsewhere →
  `L_i = B_i × M_l` isolates the strict-loser component
- Apply a **marginal mask** `M_m`: 1 in slot k only, 0 elsewhere →
  `G_i = B_i × M_m` isolates the marginal component

All three masks are public plaintexts derived from `k`. Each mask operation
is ct × pt (depth 0).

### Step 2: Handle strict winners

If the order is priced above clearing (`price > P*`), the order is fully
filled. The ciphertext is dropped (no carry-forward needed).

To report the per-order allocation, the committee threshold-decrypts the
winner's one-hot slot. Specifically, `W_i = B_i × M_w` isolates the
winner component, and the committee decrypts slot `k+1` (or the slot
corresponding to the order's price level) to learn `q_i`. The allocation
for this order is `fill_i = q_i` (full fill).

Determining whether an order is a strict winner, loser, or marginal does
**not** require decryption — it uses public price metadata. The per-order
decryption is only needed for allocation reporting.

### Step 3: Handle strict losers

If the order is priced below clearing, allocation is zero. **Keep `V_i`
(or `B_i`) unchanged** as the carried-forward ciphertext.

### Step 4: Handle marginal bidders

For orders priced exactly at `P*`:

1. **Threshold-decrypt `G_i`**: The committee decrypts only slot `k` of the
   masked ciphertext, revealing `q_i` (the bidder's quantity at the clearing
   price).

2. **Compute pro-rata allocation** in plaintext: Using all marginal
   quantities, epoch metadata, and the remaining supply after strict winners
   are filled, compute `allocate_fba(...)` as before.

3. **Compute residual**: `r_i = q_i - fill_i`.

4. **Re-encrypt residual**: The committee constructs a plaintext with `r_i`
   at slot `k` and zeros elsewhere, encrypts it with the joint public key,
   and uses this as the carried-forward ciphertext. The bidder is not
   involved.

5. **Rerandomization**: Add `Enc(0)` to the re-encrypted residual to prevent
   transcript-level linkability.

### Step 5: Assemble next-round book

The next round's ciphertext book consists of:
- Loser ciphertexts (unchanged or rerandomized)
- Marginal residual ciphertexts (committee re-encrypted)
- Newly submitted ciphertexts (from the next epoch's submission window)

All are in one-hot form (new submissions are converted via §3.3 before or
during aggregation).

## 5. FHE Circuit Analysis

### 5.1 Operations Per Round

| Operation | Type | Depth | Count |
|-----------|------|-------|-------|
| Adjacent difference (§3.3) | ct×pt + ct−ct | 0 | Per active order |
| Winner/loser/marginal mask | ct×pt | 0 | Per active order |
| Aggregate one-hot sum | ct+ct | 0 | N-1 additions |
| Threshold decrypt aggregate | decrypt | — | 1 ciphertext |
| Threshold decrypt winners | decrypt | — | Per strict winner |
| Threshold decrypt marginal | decrypt | — | Per marginal order |
| Re-encrypt residual | encrypt | — | Per marginal order |
| Rerandomize carry-forward | ct+ct (Enc(0)) | 0 | Per carried order |

### 5.2 Comparison: v1 (Naive) vs v2 (Hybrid)

| Feature | v1 (Naive) | v2 (Hybrid) |
|---------|------------|-------------|
| Bidder interaction after submit | Re-encrypt residual each round | None — submit once |
| Per-order decryptions | 2 slots × every order × every round | 1 slot × non-loser orders only; losers: 0 |
| Aggregator learns | Individual (qty_at, qty_above) for all | Quantities of winners + marginals only |
| Depth consumed | 0 | 0 |
| Extra FHE ops | None | Adjacent diff + masks per order |

### 5.3 Parameter Sufficiency

Same as M1. Parameters N=2048, t=12289, 6×62-bit moduli are sufficient.
The adjacent-difference and masking operations are all depth 0 (ct×pt and
ct±ct). The depth-1 budget remains entirely available.

### 5.4 Noise Budget

Each carry-forward round adds:
- 1 column rotation (for adjacent diff)
- 2-3 ct×pt multiplications (masks)
- 1 ct−ct subtraction
- ct+ct additions for aggregation

These are all depth-0 operations but each adds a small amount of noise.
After several rounds, noise may accumulate on long-lived loser ciphertexts.
With 6×62-bit moduli and depth-1 budget unused, the noise margin is generous
— conservatively supporting 10+ rounds of carry-forward before noise becomes
a concern.

For very long-lived orders, the committee can "refresh" a ciphertext by
threshold-decrypting and re-encrypting it, at the cost of revealing the
quantity to the committee.

## 6. Clearing Price Computation

Same as M1, but operating on the one-hot histogram rather than a cumulative
vector. After threshold-decrypting the aggregate one-hot ciphertext, the
committee obtains histogram `H[p]` (total demand at each price level).
The cumulative demand curve is computed in plaintext:

```
D[P-1] = H[P-1]
D[p] = D[p+1] + H[p]    for p = P-2 down to 0
```

Then find the highest index `k` where `D[k] >= supply`.

## 7. Allocation Computation

### 7.1 Cross-Batch Time Priority

Identical to v1. When multiple bidders are at the marginal price `P*`:

1. **Epoch Priority**: Earlier-epoch orders filled first.
2. **Pro-rata within epoch**: Largest-remainder rounding with order-id tiebreak.

### 7.2 Per-Order Quantity Discovery

Order prices are public metadata in `BatchState`. The committee classifies
each order using the public clearing index `k`:

- **Strict winners** (`price > price_ladder[k]`): Committee threshold-decrypts
  `W_i` (masked one-hot ciphertext) to learn `q_i`. Allocation = `q_i`
  (full fill). Ciphertext dropped.
- **Strict losers** (`price < price_ladder[k]`): Allocation = 0. No
  decryption needed. Ciphertext carried forward.
- **Marginal** (`price == price_ladder[k]`): Committee threshold-decrypts
  `G_i` to learn `q_i`. Pro-rata allocation computed in plaintext.
  Residual re-encrypted by committee.

**`Order.qty` remains on `BatchState`** for shadow verification in the demo,
but the FHE allocation path does not read it. The FHE path derives per-order
quantities exclusively from threshold decryption of masked ciphertexts.

### 7.3 Allocation With Decrypted Quantities

The `allocate_fba` function receives:
- The decrypted aggregate demand curve (public)
- Clearing index `k` and clearing price (public)
- For each non-loser order: decrypted quantity `q_i` from the FHE path
- Each order's `epoch` and `order_id` (public metadata)

It returns per-order allocations:
- Strict winners: `fill_i = q_i` (full fill, quantity from decryption)
- Strict losers: `fill_i = 0`
- Marginal: pro-rata from decrypted quantities, with epoch priority

## 8. Protocol Flow

```
Round n Window  ──►  Round n Match  ──►  Carry-Forward  ──►  Round n+1 Window
     │                    │                    │                    │
Submit bids          Sum one-hots         Classify orders     Submit new bids
(encrypt once)       Decrypt aggregate    Winners: decrypt    (encrypt once)
                     Find clearing k        qty, drop ct
                     Decrypt non-losers   Losers: keep ct
                     Allocate             Marginals: decrypt,
                                            compute residual,
                                            re-encrypt
```

1. **Submission**: Bidders encrypt `(qty, price)` as cumulative demand vector,
   submit once. Never interact again.
2. **Conversion**: Aggregator converts all active ciphertexts to one-hot form
   via adjacent differencing (§3.3).
3. **Aggregation**: Sum all one-hot ciphertexts → aggregate histogram.
4. **Decryption**: Committee threshold-decrypts aggregate histogram.
5. **Clearing**: Compute cumulative demand from histogram, find clearing price.
6. **Classification**: Using public price metadata, classify each order.
7. **Non-loser decryption**: Committee threshold-decrypts winners' and
   marginals' masked one-hot slots to learn individual quantities.
8. **Allocation**: Compute fills using decrypted quantities, epoch priority + pro-rata.
9. **Carry-forward**: Committee re-encrypts marginal residuals. Loser
   ciphertexts kept. Winner ciphertexts dropped.
10. **Cancellation**: Bidders can request removal before step 3.

## 9. Implementation Plan

### Phase 1: Library changes (`src/lib.rs`)

New functions:
- `to_one_hot(ct, eval_key, params) -> Ciphertext`: Adjacent-difference
  transform. Takes a cumulative-form ciphertext, returns one-hot form.
  Uses `eval_key.rotates_columns_by(&ct, 1)`, a zero-guard mask, and
  subtraction.
- `build_classification_masks(clearing_idx, params) -> (Plaintext, Plaintext, Plaintext)`:
  Returns `(winner_mask, loser_mask, marginal_mask)` for slots k+1..P-1,
  0..k-1, and k respectively.
- `apply_mask(ct, mask) -> Ciphertext`: ct × pt multiplication.
- `decrypt_one_hot_slot(ct, mask, slot_idx, participating, sk_poly_sums, params) -> u64`:
  Mask + threshold-decrypt a single order's one-hot quantity at the given
  slot. Used for both winners (slot = order's price index) and marginals
  (slot = k).
- `encrypt_one_hot_residual(qty, clearing_idx, price_ladder, params, pk) -> Ciphertext`:
  Committee re-encrypts a residual quantity at the marginal price slot.
- `accumulate_one_hot(global, contribution)`: Same as `accumulate_demand`
  but semantically named for one-hot vectors. (May just alias it.)
- `histogram_to_demand_curve(histogram: &[u64]) -> Vec<u64>`: Suffix-sum
  in plaintext.

Modified:
- `allocate_fba`: Accept a map of decrypted quantities (from FHE path) for
  non-loser orders, rather than reading from `Order.qty`. `Order.qty`
  remains on the struct for shadow verification but is not used by the
  FHE allocation path.

**QA**: `cargo test --lib` from `examples/batch-auction-fba/`. Expected:
all existing tests pass, plus new unit tests for `to_one_hot`,
`build_classification_masks`, `histogram_to_demand_curve`, and
`decrypt_one_hot_slot`.

### Phase 2: Demo binary (`src/bin/demo.rs`)

Rewrite the demo to use the homomorphic carry-forward flow:
- Bidders submit encrypted orders once and never re-encrypt.
- Between rounds, the aggregator converts ciphertexts to one-hot form via
  adjacent differencing, then sums them.
- Committee threshold-decrypts the aggregate histogram.
- Committee threshold-decrypts each non-loser order's masked one-hot slot
  to learn individual quantities for allocation.
- For marginal bidders, committee computes residual and re-encrypts.
- Loser ciphertexts carry forward untouched.
- Shadow verification confirms FHE results match plaintext simulation.

Same scenario: 10 bidders, 3 rounds, cancellation in round 2.

**QA**: `cargo run --bin demo --release` from `examples/batch-auction-fba/`.
Expected: all rounds clear correctly, shadow verification passes, exit 0.

### Phase 3: Unit tests

- `test_to_one_hot`: Verify adjacent-difference produces correct one-hot
  vector for various (qty, price) pairs.
- `test_classification_masks`: Verify masks isolate correct slot ranges.
- `test_histogram_to_demand_curve`: Verify suffix-sum produces correct
  cumulative demand.
- `test_decrypt_and_reencrypt`: Verify committee can decrypt a one-hot slot,
  compute residual, and re-encrypt correctly.
- `test_carry_forward_homomorphic`: End-to-end test: submit, clear, carry
  forward without bidder re-encryption, verify next round aggregation.
- `test_loser_noise_budget`: Verify a ciphertext survives multiple rounds
  of masking + aggregation without noise corruption.

**QA**: `cargo test --lib` from `examples/batch-auction-fba/`. Expected:
all tests pass.

## 10. Edge Cases

| Case | Handling |
|------|----------|
| All orders are strict winners | No marginal decryption needed. No carry-forward. |
| All orders are strict losers | No decryption beyond aggregate. All ciphertexts carry forward. |
| All orders are marginal | Every order's slot `k` is decrypted. Maximum per-order disclosure. |
| Zero marginal bidders | Clearing price falls between two price levels. No pro-rata needed. |
| Order cancelled after partial fill | Valid; ciphertext removed from book before next aggregation. |
| Noise accumulation on long-lived losers | Monitor noise budget. Committee can refresh by decrypt+re-encrypt after many rounds. |
| Clearing at lowest price (k=0) | Loser mask is empty (no slots below 0). All non-winners are marginal. |
| Clearing at highest price (k=P-1) | Winner mask is empty. All non-losers are marginal. |
| Column rotation wraparound | Zero-guard mask prevents slot P (or slot 1024) from bleeding into slot 0. |

## 11. Privacy Analysis

| Information | Who learns it | When |
|-------------|---------------|------|
| Aggregate demand histogram | Committee (2-of-3) | Each round |
| Clearing price and index | Public | Each round |
| Individual quantity (winners) | Committee (2-of-3) | Round where order is filled |
| Individual quantity (marginal bidders) | Committee (2-of-3) | Round where order is marginal |
| Individual quantity (strict losers) | Nobody | Never (until filled or cancelled) |
| Order price level | Public | Submission time (stored in `Order`) |
| Order epoch | Public | Submission time |

**Improvement over v1**: In v1, the committee decrypted 2 slots per bidder
per round (demand at clearing + demand above clearing) for every active order.
In v2, only non-loser orders have one slot decrypted per round. Strict losers
— which may be the majority of orders in a deep book — have zero per-order
information revealed. Bidders never need to interact after initial submission.

## 12. Open Questions

1. **Secret prices**: If order prices should also be secret, classification
   would require per-order masked decryption of indicator slots. This demo
   treats prices as public.
2. **Committee MPC for marginals**: Instead of the committee learning marginal
   quantities in cleartext, they could compute pro-rata in an MPC protocol
   over secret shares, further reducing information leakage.
3. **Dynamic price ladders**: Can the ladder shift between epochs?
