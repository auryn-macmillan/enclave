# Two-Sided Batch Exchange, FHE Circuit Design

> **Milestone**: M4 precursor — single-pair two-sided exchange (see `AGENTS.md` §M4 for the full multi-pair scope)
> **Status**: Design complete, implementation pending
> **Infrastructure**: Threshold BFV (2-of-3 committee), distributed DKG + eval-key MPC
> **Scope note**: This document covers a single trading pair only. The full M4 milestone (multi-pair combinatorial matching) will build on this foundation as a subsequent extension.

## 1. Problem Statement

A sealed-bid **two-sided batch exchange** for a single trading pair (Asset A / Asset B). Participants act as either buyers or sellers.

1.  **Buyers**: Submit encrypted `(quantity, max_price)` pairs. They're willing to buy Asset A using Asset B at any price up to `max_price`.
2.  **Sellers**: Submit encrypted `(quantity, min_price)` pairs. They're willing to sell Asset A for Asset B at any price from `min_price` upwards.

The FHE program determines:

1.  **Clearing price `P*`**: The highest discrete price level where aggregate buy demand is greater than or equal to aggregate sell supply.
2.  **Per-participant allocation**:
    - **Buyers**:
- `max_price_i > P*` (full `quantity_i`, strict winner)
- `max_price_i < P*` (0, loser)
- `max_price_i == P*` (pro-rata share of remaining volume if buy-side is marginal)
- **Sellers**:
- `min_price_j < P*` (full `quantity_j`, strict winner)
- `min_price_j > P*` (0, loser)
- `min_price_j == P*` (pro-rata share of remaining volume if sell-side is marginal)

**Privacy guarantee**: Only the aggregate demand/supply curves, clearing price, and per-participant allocations are revealed. Individual `(quantity, price)` pairs remain encrypted.

## 2. Key Insight: Two Cumulative Vectors

Similar to the one-sided auction (M1), we move comparisons into the encoding phase. However, M4 requires two aggregate curves on the same price grid.

-   **Buy Demand**: A descending step function. Demand is highest at low prices and decreases as price rises.
-   **Sell Supply**: An ascending step function. Supply is lowest at low prices and increases as price rises.

The clearing price is the intersection of these two curves. By encoding both sides into the same BFV SIMD slots (mapped to price levels), we can compute both aggregate curves using only homomorphic addition.

## 3. Encoding Scheme

### 3.1 Price Ladder

Define `P` discrete price levels as a public ascending ladder:

```
price_ladder = [p_0, p_1, ..., p_{P-1}]   (p_0 < p_1 < ... < p_{P-1})
```

For the demo, `P = 64`.

### 3.2 Buyer Encoding (Descending Step)

Buyer `i` with `(q_i, max_price_i)` constructs:

```
v_buy_i[p] = q_i    if price_ladder[p] <= max_price_i
v_buy_i[p] = 0      if price_ladder[p] > max_price_i
```

### 3.3 Seller Encoding (Ascending Step)

Seller `j` with `(q_j, min_price_j)` constructs:

```
v_sell_j[p] = q_j    if price_ladder[p] >= min_price_j
v_sell_j[p] = 0      if price_ladder[p] < min_price_j
```

### 3.4 Example

Price ladder: `[10, 20, 30, 40, 50]`
- Buyer A: `(qty=100, max_price=30)` → `[100, 100, 100, 0, 0]`
- Seller B: `(qty=150, min_price=20)` → `[0, 150, 150, 150, 150]`

### 3.5 Accumulation

The aggregator maintains two encrypted accumulators:

```
V_buy  = Σ_i v_buy_i
V_sell = Σ_j v_sell_j
```

Both use `n-1` homomorphic additions (depth 0).

## 4. FHE Circuit Analysis

### 4.1 Operations Required

| Phase | Operation | FHE Cost | Depth |
|-------|-----------|----------|-------|
| Encoding | Client-side step-function | None | 0 |
| Encryption | `pk.encrypt(v)` | 1 per participant | 0 |
| Accumulation | `Σ v_buy`, `Σ v_sell` | n_buy + n_sell - 2 additions | 0 |
| Masking | `V × slot_mask` | 2 ct×pt multiplies | 0 |
| Threshold decrypt | Decrypt curves + masks | Standard protocol | 0 |

**Total multiplicative depth: 0.**

### 4.2 Noise and Range Constraints

-   **Noise**: Handled by existing 6×62-bit moduli.
-   **Range**: `Σ q_buy < t/2` and `Σ q_sell < t/2`.
-   **t = 12289**: Sum of all buy quantities (and sell quantities) must be `< 6144`.

### 4.3 Parameter Sufficiency

Identical to M1. No parameter changes needed.

## 5. Clearing Price Computation

After decrypting `V_buy` and `V_sell`:

```rust
fn find_clearing_price(
    buy_demand: &[u64],
    sell_supply: &[u64],
    price_ladder: &[u64],
) -> Option<(usize, u64)> {
    // Walk from highest price down. 
    // Find highest p where demand >= supply.
    for p in (0..price_ladder.len()).rev() {
        if buy_demand[p] >= sell_supply[p] && sell_supply[p] > 0 {
            return Some((p, price_ladder[p]));
        }
    }
    None // No intersection
}
```

## 6. Allocation Computation

### 6.1 Slot Extraction Per Side

Buyers and sellers use **different** adjacent slot pairs for allocation
extraction because their encoding directions are opposite:

- **Buyers** (descending step): extract slots `k` and `k+1`.
  - `strict_fill_buy_i = v_buy_i[k+1]` (quantity above `P*`)
  - `marginal_qty_buy_i = v_buy_i[k] - v_buy_i[k+1]` (quantity at exactly `P*`)
  - When `k == P-1` (highest ladder price): `v_buy_i[k+1] = 0`, so all demand is marginal.

- **Sellers** (ascending step): extract slots `k` and `k-1`.
  - `strict_fill_sell_j = v_sell_j[k-1]` (quantity below `P*`)
  - `marginal_qty_sell_j = v_sell_j[k] - v_sell_j[k-1]` (quantity at exactly `P*`)
  - When `k == 0` (lowest ladder price): `v_sell_j[k-1] = 0`, so all supply is marginal.

The committee constructs **two** plaintext masks per side:
- Buyer mask: 1 at slots `k` and `k+1`, 0 elsewhere.
- Seller mask: 1 at slots `k` and `k-1`, 0 elsewhere (or just `k` when `k == 0`).

### 6.2 Determining the Rationed Side

At clearing price index `k`:
- If `buy_demand[k] > sell_supply[k]`:
    - Matched volume = `sell_supply[k]`.
    - Sellers at or below `P*` are filled in full.
    - Buyers are rationed (marginal buyers pro-rata'd).
- If `sell_supply[k] > buy_demand[k]`:
    - Matched volume = `buy_demand[k]`.
    - Buyers at or above `P*` are filled in full.
    - Sellers are rationed (marginal sellers pro-rata'd).
- If `equal`: Both sides filled in full.

### 6.3 Pro-rata and Rounding

Rationing uses the same largest-remainder method as M1. Only the "marginal" side at index `k` receives pro-rata allocations. Strict winners (buyers above `P*`, sellers below `P*`) always get 100%.

## 7. Protocol Flow

1.  **DKG/Eval-Key**: Setup joint keys.
2.  **Submission**:
    - Buyers encrypt descending vectors.
    - Sellers encrypt ascending vectors.
3.  **Aggregation**: Aggregator sums buy ciphertexts and sell ciphertexts separately.
4.  **Decryption**:
    - Threshold-decrypt `V_buy` and `V_sell`.
    - Committee finds `P*`.
    - Committee identifies which side is rationed.
    - Committee masks buyer vectors at slots `k` and `k+1`; seller vectors at slots `k` and `k-1` (or just `k` when `k == 0`).
    - Threshold-decrypt masked vectors.
5.  **Settlement**: Compute final allocations with largest-remainder rounding.

## 8. Comparison: M1 vs M4

| Aspect | M1 (One-Sided) | M4 (Two-Sided) |
|--------|----------------|----------------|
| Input | Bidders | Buyers + Sellers |
| Supply | Public constant | Dynamic (from Sellers) |
| Curves | 1 (Demand) | 2 (Demand + Supply) |
| Clearing | Demand vs Constant | Demand vs Supply |
| Rationing | Always Buy-side | Either Buy or Sell-side |
| Depth | 0 | 0 |

## 9. Ciphertext Count

- Buyers: `n_buy`
- Sellers: `n_sell`
- Aggregates: 2
- Total threshold decryptions: `2 + n_buy + n_sell`

## 10. Edge Cases

| Case | Handling |
|------|----------|
| No intersection | No trades occur. |
| Empty side | No trades occur. |
| Exact intersection | Both sides filled 100%, no rationing. |
| All buyers at same price | Standard pro-rata if rationed. |
| Single buyer + seller | Match at highest price where `demand >= supply` within the overlap range (i.e., `max_price` of the buyer, provided `max_price >= min_price` of the seller). |

## 11. Implementation Plan

### Phase 1: Scaffolding
- Create `examples/batch-exchange/Cargo.toml`.
- Link to `auction-bitplane` for common threshold BFV logic.

**QA**: `cargo check` passes.

### Phase 2: Core Library
- `encode_buy_demand_vector`: Descending step.
- `encode_sell_supply_vector`: Ascending step.
- `find_two_sided_clearing_price`: Curve intersection logic.
- `compute_two_sided_allocations`: Handles rationing on either side,
  using buyer slots `(k, k+1)` and seller slots `(k, k-1)`.

**QA**: Run `cargo test --lib` from `examples/batch-exchange/`. Expected:
all unit tests pass, including:
- `test_encode_buy_demand_vector` — descending step shape correct
- `test_encode_sell_supply_vector` — ascending step shape correct
- `test_clearing_price_basic` — correct intersection found
- `test_clearing_price_no_intersection` — returns `None`
- `test_allocations_buy_side_rationed` — buyers pro-rata'd, sellers full
- `test_allocations_sell_side_rationed` — sellers pro-rata'd, buyers full
- `test_allocations_exact_match` — both sides filled 100%

### Phase 3: Demo Binary
- 5 Buyers, 5 Sellers.
- Random prices and quantities (total < 6144).
- Shadow verification against plaintext.

**QA**: `cargo run --bin demo` prints "Verified".

### Phase 4: Extended Tests
- Edge case: no intersection.
- Edge case: rationing on sell-side.
- Edge case: rationing on buy-side.

**QA**: `cargo test` passes.
