# Uniform-Price Batch Auction — FHE Circuit Design

> **Milestone**: M1 (see `AGENTS.md`)
> **Status**: Design complete, implementation pending
> **Infrastructure**: Threshold BFV (2-of-3 committee), distributed DKG + eval-key MPC

## 1. Problem Statement

A sealed-bid **uniform-price** batch auction. Bidders submit encrypted
`(quantity, price)` pairs. A fixed supply `S` is known publicly. The FHE
program determines:

1. **Clearing price `P*`**: the highest discrete price level at which
   aggregate demand meets or exceeds supply.
2. **Per-bidder allocation**:
   - `price_i > P*` → full `quantity_i` (strict winner)
   - `price_i < P*` → 0 (loser)
   - `price_i == P*` → pro-rata share of remaining supply (marginal bidder)

**Privacy guarantee**: Only the clearing price and per-bidder allocations
are revealed. Individual `(quantity, price)` pairs are never decrypted.

## 2. Key Insight: Move Comparison into Encoding

The fundamental challenge is computing "which bids are above the clearing
price" under encryption. Direct comparison (less-than, greater-than)
requires multiplicative depth ~O(log b) for b-bit values — far exceeding
our depth-1 budget.

**Solution**: Each bidder pre-computes a **cumulative demand vector**
client-side and encrypts it. The vector encodes "at price level `p`, how
much does this bidder demand?" as a step function. Summing these vectors
across bidders produces the aggregate demand curve — **using only
homomorphic addition (depth 0)**.

This eliminates encrypted comparison entirely.

## 3. Encoding Scheme

### 3.1 Price Ladder

Define `P` discrete price levels as a public ascending ladder:

```
price_ladder = [p_0, p_1, ..., p_{P-1}]   (p_0 < p_1 < ... < p_{P-1})
```

For the demo, use `P = 64` evenly spaced levels. With `P ≤ 1024`, the
entire ladder fits in one BFV row half, avoiding row-crossing complexity.

### 3.2 Cumulative Demand Vector (per bidder)

Bidder `i` with bid `(q_i, price_i)` constructs a plaintext vector of
length `N = 2048`:

```
v_i[p] = q_i    if price_ladder[p] <= price_i
v_i[p] = 0      if price_ladder[p] > price_i
        (slots p >= P are always 0)
```

This is a step function: `q_i` in all slots up to and including the
bidder's price level, then zeros. The bidder computes this **in plaintext
before encryption** — no FHE operations needed.

**Example**: Price ladder `[10, 20, 30, 40, 50]`, bidder bids
`(qty=100, price=30)`:

```
v_i = [100, 100, 100, 0, 0, 0, 0, ...]
       p=10 p=20 p=30 p=40 p=50  (unused)
```

### 3.3 Encryption

Each bidder encrypts `v_i` as a single BFV ciphertext using SIMD encoding
with the joint public key. **One ciphertext per bidder.**

### 3.4 Accumulation

The aggregator sums all bidder ciphertexts:

```
V = Σ_i v_i
```

This is `n_bidders - 1` homomorphic additions (depth 0). The result `V`
is an encrypted vector where `V[p]` = total demand at price level `p`
(cumulative from above).

## 4. FHE Circuit Analysis

### 4.1 Operations Required

| Phase | Operation | FHE Cost | Depth |
|-------|-----------|----------|-------|
| Encoding | Client-side plaintext construction | None | 0 |
| Encryption | `pk.encrypt(v_i)` | 1 encryption/bidder | 0 |
| Accumulation | `V = Σ v_i` | n-1 ct additions | 0 |
| Masking | `V_masked = V × slot_mask` | 1 ct×pt multiply | 0 |
| Threshold decrypt | Decrypt `V_masked` | Standard protocol | — |
| Clearing price | Plaintext search on `V` | None (plaintext) | 0 |
| Allocation prep | See §6 | ct×pt multiplies | 0 |

**Total multiplicative depth: 0.**

The depth-1 budget is **not consumed** by the core demand-curve
computation. This leaves the full depth-1 multiply available for optional
allocation computation if needed (see §6).

### 4.2 Rotation Requirements

The core accumulation (addition of ciphertexts) requires **no rotations**.
Galois keys are needed only if we compute slot-wise reductions (e.g.,
summing adjacent slots for marginal-quantity extraction).

For the basic protocol, the existing 11 column-rotation + row-swap Galois
keys are sufficient but mostly unused. This is a bonus — the circuit is
simpler than Vickrey.

### 4.3 Noise Budget

Each ct addition grows noise additively. With `n` bidders:
- Fresh ciphertext noise: σ
- After `n-1` additions: ~n·σ
- With 6×62-bit moduli (372-bit total), noise budget is ~330 bits
- Each addition costs ~1 bit, so we can handle thousands of bidders
- The mask (ct×pt) costs a few more bits but is negligible

**Verdict**: Current parameters handle up to ~2048 bidders with margin.

### 4.4 Plaintext Range Constraint

BFV arithmetic is mod `t = 12289`. The cumulative demand at any price
level must satisfy:

```
V[p] = Σ{q_i : price_i ≥ price_ladder[p]} < t/2 = 6144
```

Values above `t/2` are ambiguous with negative values / noisy zeros.

**Implication**: Total demand at the lowest price level (where everyone
participates) must be < 6144. For the demo, cap individual quantities
to reasonable ranges (e.g., 1–500) with ~10 bidders → max total ~5000.

For production with larger quantities, options include:
- Increase `t` (requires parameter change)
- Multi-limb encoding (split quantity into low/high halves)
- Bit-decompose quantities into multiple ciphertexts per bidder

### 4.5 Parameter Sufficiency

| Parameter | Current | Needed | Verdict |
|-----------|---------|--------|---------|
| N (degree) | 2048 | 2048 | Sufficient (P ≤ 1024 fits in one row) |
| t (plaintext mod) | 12289 | 12289 | Sufficient for demo (total demand < 6144) |
| Moduli | 6×62-bit | 6×62-bit | Sufficient (depth 0, huge noise margin) |
| Galois keys | 11 rotations | 0–11 | Sufficient (mostly unused) |
| Relin key | 1 | 0–1 | Sufficient (unused unless depth-1 alloc) |

**No parameter changes needed for M1.**

## 5. Clearing Price Computation

After threshold-decrypting the aggregate demand vector `V`:

```rust
fn find_clearing_price(
    demand_curve: &[u64],  // decrypted V[0..P]
    supply: u64,
    price_ladder: &[u64],
) -> (usize, u64) {
    // Walk from highest price down to find where demand >= supply.
    for p in (0..demand_curve.len()).rev() {
        if demand_curve[p] >= supply {
            return (p, price_ladder[p]);
        }
    }
    // Undersupply: total demand < supply at all price levels.
    // Clear at the lowest price — all bidders are filled in full.
    (0, price_ladder[0])
}
```

### 5.1 Undersupply Semantics

When total demand at the lowest price level is less than supply
(`demand_curve[0] < supply`), the auction **does not fail**. Instead:

- Clearing price is set to `price_ladder[0]` (the lowest level).
- All bidders are treated as strict winners — every bid is at or above
  the clearing price.
- Every bidder receives their full requested quantity.
- Remaining supply is unallocated (the auction is undersubscribed).

This matches standard uniform-price auction semantics: if the market
doesn't clear, every willing buyer gets what they asked for at the
lowest accepted price.

### 5.2 Clearing Price Derivation

The clearing price index `k` gives us:

- `P* = price_ladder[k]` — the clearing price
- `D_at_P* = demand_curve[k]` — total demand at P*
- `D_strict = demand_curve[k+1]` — demand strictly above P* (if k+1 < P)
  - If `k == P-1`, then `D_strict = 0`
- `Q_marginal = D_at_P* - D_strict` — total marginal quantity
- `R = supply - D_strict` — remaining supply for marginal bidders

## 6. Allocation Computation

### 6.1 Non-Marginal Allocation (Exact)

For bidders with `price_i > P*`: allocation = `q_i` (full fill).
For bidders with `price_i < P*`: allocation = 0.

These are determined entirely by the bidder's cumulative demand vector.
The bidder's slot at price index `k+1` (one above clearing) gives their
strict-winner quantity directly:

```
strict_fill_i = v_i[k+1]   (= q_i if price_i > P*, else 0)
```

### 6.2 Marginal Allocation

For bidders at exactly `price_i == P*`:

```
marginal_qty_i = v_i[k] - v_i[k+1]   (= q_i if at clearing, else 0)
```

The pro-rata share uses **largest-remainder rounding** to ensure integer
allocations sum exactly to `R` (remaining supply for marginal bidders):

```rust
fn allocate_marginal(
    marginal_qtys: &[(usize, u64)],  // (bidder_slot, marginal_qty_i)
    remaining_supply: u64,            // R = supply - D_strict
    total_marginal: u64,              // Q_marginal = Σ marginal_qty_i
) -> Vec<(usize, u64)> {
    if total_marginal == 0 {
        // No marginal bidders — nothing to allocate.
        return marginal_qtys.iter().map(|&(s, _)| (s, 0)).collect();
    }

    // Step 1: Compute floor allocations and fractional remainders.
    let mut entries: Vec<(usize, u64, f64)> = marginal_qtys
        .iter()
        .map(|&(slot, mq)| {
            let exact = (mq as f64) * (remaining_supply as f64) / (total_marginal as f64);
            let floor = exact.floor() as u64;
            let remainder = exact - floor as f64;
            (slot, floor, remainder)
        })
        .collect();

    // Step 2: Distribute leftover units by largest remainder.
    let floor_sum: u64 = entries.iter().map(|(_, f, _)| f).sum();
    let mut leftover = remaining_supply - floor_sum;

    // Sort by remainder descending; break ties by lower slot index.
    entries.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap().then(a.0.cmp(&b.0)));

    entries.iter_mut().for_each(|(_, floor, _)| {
        if leftover > 0 {
            *floor += 1;
            leftover -= 1;
        }
    });

    // Return in original order (by slot index).
    entries.sort_by_key(|(slot, _, _)| *slot);
    entries.iter().map(|&(s, f, _)| (s, f)).collect()
}
```

**Rounding rule**: Largest-remainder method (Hamilton's method).
**Tiebreak**: When two bidders have equal fractional remainders, the
bidder with the **lower slot index** receives the extra unit first.
This is deterministic and publicly verifiable.

### 6.3 Settlement Modes

**Mode A: Exact settlement (decrypt marginal quantities)**

1. From the decrypted demand curve, compute `P*`, `D_strict`, `Q_marginal`, `R`.
2. Threshold-decrypt each bidder's ciphertext `v_i` at slots `k` and `k+1` only.
   - Actually: decrypt the full `v_i` for each bidder, but extract only
     slots `k` and `k+1`. Or use a plaintext mask to zero all other slots
     before decryption, limiting information leakage.
3. Compute `strict_fill_i = v_i[k+1]`, `marginal_qty_i = v_i[k] - v_i[k+1]`.
4. Compute exact pro-rata in plaintext with deterministic rounding.

**Privacy note**: Decrypting `v_i[k]` and `v_i[k+1]` reveals:
- Whether bidder `i` is a strict winner, marginal, or loser
- If marginal: their exact quantity at the clearing price
This is the minimum leakage needed for exact pro-rata. Individual prices
are not revealed (only their relation to `P*`).

**Implementation for M1**: Use a plaintext mask that is 1 at slot `k`,
1 at slot `k+1`, and 0 elsewhere. Multiply each bidder's ciphertext by
this mask (ct×pt, depth 0), then threshold-decrypt. This reveals only
the two relevant slots.

**Mode B: Private approximate settlement (homomorphic pro-rata)**

Apply a public scaling factor `F = R / Q_marginal` (computed in plaintext
from the demand curve) homomorphically:

```
alloc_i = v_i[k+1] + (v_i[k] - v_i[k+1]) × F
```

This requires ct×pt multiplies (depth 0) and would reveal only the final
allocation amount per bidder. However, `F` is a fraction — representing
it in `Z_t` requires computing the modular inverse of `Q_marginal` mod `t`,
which exists since `t = 12289` is prime.

**Trade-off**: More private but may have rounding artifacts. For M1,
**Mode A is recommended** — simpler, exact, and the leakage (position
relative to clearing price) is inherent to any uniform-price auction.

## 7. Protocol Flow

```
┌─────────────┐
│  Committee   │  1. DKG: generate joint public key (same as Vickrey)
│  (2-of-3)   │  2. Eval-key MPC: Galois + relin keys (same as Vickrey)
└──────┬──────┘
       │ joint public key
       ▼
┌─────────────┐
│   Bidders    │  3. Each bidder encodes (qty, price) as cumulative
│  (1..n)      │     demand vector and encrypts with joint public key
└──────┬──────┘
       │ encrypted v_i ciphertexts
       ▼
┌─────────────┐
│ Aggregator   │  4. Sum all v_i → V (aggregate demand curve)
└──────┬──────┘
       │ V (encrypted aggregate demand)
       ▼
┌─────────────┐
│  Committee   │  5. Threshold-decrypt V → demand curve in plaintext
│  (2-of-3)   │  6. Find clearing price P* via plaintext search
│              │  7. Construct allocation mask for slots k, k+1
│              │  8. For each bidder: mask v_i, threshold-decrypt
│              │     → extract strict_fill and marginal_qty
│              │  9. Compute final allocations (exact pro-rata)
└─────────────┘
```

## 8. Comparison with Vickrey Demo

| Aspect | Vickrey | Uniform-Price Batch |
|--------|---------|---------------------|
| Bid type | Single scalar (price) | (quantity, price) pair |
| Encoding | 64 bitplane ciphertexts/bidder | 1 cumulative-demand ciphertext/bidder |
| FHE computation | Tally per bitplane (depth 1) | Sum across bidders (depth 0) |
| Rotations used | 11 per bitplane × 64 = 704 | 0 for core; optional for allocation |
| Relin used | Yes (64 relinearizations) | No (for core computation) |
| Depth consumed | 1 | 0 (core), optionally 0 (allocation via ct×pt) |
| Decryption surface | 64 tally ciphertexts + winner's bid | 1 aggregate vector + n×1 masked bidder vectors |
| Privacy | Individual bids never decrypted | Individual (qty, price) pairs never revealed |
| Complexity | O(BID_BITS × n) rotations | O(n) additions |

## 9. Ciphertext Count and Performance

| Component | Count | Notes |
|-----------|-------|-------|
| Bidder ciphertexts | n | One per bidder |
| Aggregate demand | 1 | Sum of all bidder ciphertexts |
| Masked bidder vectors | n | For allocation extraction |
| **Total threshold decryptions** | **1 + n** | Demand curve + per-bidder allocation |

For 10 bidders: 11 threshold decryptions (vs. 64 + 64 = 128 for Vickrey).
Significantly lighter.

## 10. Edge Cases

| Case | Handling |
|------|----------|
| Total demand < supply at all prices | Undersupply: clear at lowest price, all bidders filled in full (see §5.1) |
| All bids at same price | All marginal; pro-rata entire supply via largest-remainder (see §6.2) |
| Single bidder | Clearing at their price; full fill up to supply |
| Quantity exceeds supply | Standard marginal pro-rata with largest-remainder rounding |
| Zero quantity bid | Valid; contributes nothing to demand curve |
| Demand curve wraps mod t | **Bug**: must enforce `Σq_i < t/2` |
| Equal fractional remainders | Tiebreak by lower slot index (deterministic, see §6.2) |
| R = 0 (exact fill at clearing) | All marginal bidders get 0 marginal allocation; strict winners only |

## 11. Implementation Plan

### Phase 1: Crate scaffolding
- `examples/batch-auction-uniform/Cargo.toml`
- Reuse imports from `auction-bitplane` (add as path dependency)

**QA**: Run `cargo check` from `examples/batch-auction-uniform/`. Expected:
compiles with zero errors, all dependencies resolve.

### Phase 2: Core library (`src/lib.rs`)
1. **Constants**: `PRICE_LEVELS = 64`, `SLOTS = 2048`, committee params (reuse)
2. **`build_price_ladder(min, max, levels)`**: Generate evenly-spaced discrete price levels
3. **`encode_demand_vector(qty, price, price_ladder, params)`**: Bidder encodes `(qty, price)` → cumulative vector plaintext
4. **`encrypt_demand(plaintext, pk)`**: Encrypt cumulative vector
5. **`accumulate_demand(global, contribution)`**: Sum bidder ciphertexts (`global += contribution`)
6. **`find_clearing_price(demand_curve, supply, price_ladder)`**: Plaintext search on decrypted demand curve → `(clearing_idx, clearing_price)`
7. **`compute_allocations(bidder_slots, clearing_idx, supply, demand_curve)`**: Extract strict/marginal fills, pro-rata via largest-remainder
8. Reuse from auction-bitplane: `build_params`, `generate_crp`, `member_keygen`, `aggregate_public_key`, `aggregate_sk_shares_for_party`, `build_eval_key_from_committee`, `generate_eval_key_root_seed`, `generate_smudging_noise`, `compute_decryption_shares`, `threshold_decrypt`

**QA**: Run `cargo test --lib` from `examples/batch-auction-uniform/`. Expected:
all unit tests pass (encoding round-trip, clearing price search, allocation
arithmetic including edge cases).

### Phase 3: Demo binary (`src/bin/demo.rs`)
- 10 bidders, random (qty, price) pairs within price ladder range
- Enforce `Σq_i < t/2 = 6144` (cap individual quantities accordingly)
- Full pipeline: DKG → encrypt → aggregate → decrypt → find clearing → allocate
- Shadow plaintext verification: compute expected results from plaintext bids,
  assert FHE-derived clearing price and allocations match exactly

**QA**: Run `cargo run --bin demo --release` from `examples/batch-auction-uniform/`.
Expected: prints bidder submissions, clearing price, per-bidder allocations,
shadow verification results. Exits with code 0 and prints "Verified" on success.
All `assert_eq!` checks pass.

### Phase 4: Tests
- Unit tests for `encode_demand_vector`: verify step-function shape, boundary slots
- Unit tests for `find_clearing_price`: oversupply, undersupply, exact-match, single-bidder
- Unit tests for `compute_allocations` / `allocate_marginal`: all-marginal, no-marginal,
  remainder distribution, tiebreak by slot index, R=0 case
- End-to-end FHE pipeline test (like Vickrey's `e2e_single_bidder_pipeline`)
- Edge cases: undersupply (all bidders filled, clearing at lowest price),
  oversupply (pro-rata marginal), all bids at same price, single bidder

**QA**: Run `cargo test --release` from `examples/batch-auction-uniform/`.
Expected: all tests pass. Specifically:
- `test_encode_demand_vector_step_shape` — asserts correct slot values
- `test_clearing_price_undersupply` — asserts clearing at index 0
- `test_clearing_price_oversupply` — asserts correct clearing index
- `test_allocations_all_marginal` — asserts largest-remainder distribution
- `test_allocations_no_marginal` — asserts strict fills only
- `test_e2e_fhe_pipeline` — asserts FHE matches plaintext shadow

## 12. Open Questions for Future Milestones

1. **Larger quantity ranges**: Multi-limb encoding or increased `t`?
2. **Private pro-rata (Mode B)**: Worth implementing for M2/M3?
3. **Time-window semantics (M2)**: How to handle accumulation over time?
4. **ZK proofs for valid bids**: Prove quantity > 0, price within ladder?
5. **Multiple price ladders**: Different assets in M4?
