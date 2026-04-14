# Capped Token Sale (Fair Launch) — FHE Circuit Design

> **Milestone**: M3 (see `AGENTS.md`)
> **Status**: Design complete, implementation pending
> **Infrastructure**: Threshold BFV (2-of-3 committee), distributed DKG + eval-key MPC

## 1. Problem Statement

A sealed-bid **capped token sale** (Fair Launch). Bidders submit encrypted
`(lots, price)` pairs. A fixed supply of tokens is available, denominated in
discrete **lots**. A public **per-bidder cap** `K` limits the maximum number
of lots any single participant can request. The FHE program determines:

1. **Clearing price `P*`**: the highest discrete price level at which
   aggregate demand for lots meets or exceeds the total lot supply.
2. **Per-bidder allocation**:
   - `price_i > P*` → full `lots_i` (strict winner)
   - `price_i < P*` → 0 (loser)
   - `price_i == P*` → pro-rata share of remaining lots (marginal bidder)

**Privacy guarantee**: Only the clearing price and per-bidder allocations
(in lots) are revealed. Individual bids and un-clamped quantities are never decrypted.

## 2. Key Insight: Lot-Unit Encoding and Client-Side Clamping

To ensure fairness and prevent whale dominance, the sale enforces a public
cap `K` on the number of lots per bidder.

**Solution**:
1. **Lot-units**: All quantities are expressed in discrete lots (e.g., 1 lot = 100 tokens). This simplifies allocation to integer units and naturally fits the SIMD slot range.
2. **Client-side clamping**: Instead of expensive encrypted comparisons, the cap `K` is enforced by the client-side encoding function. If a bidder attempts to request `Q > K` lots, the encoder produces a demand vector for exactly `K` lots.
3. **Cumulative Demand Vector**: Same as M1, each bidder encrypts a step function representing their demand at each price level. Summing these produces the aggregate demand curve with **zero multiplicative depth**.

## 3. Encoding Scheme

### 3.1 Price Ladder

Define `P` discrete price levels as a public ascending ladder:

```
price_ladder = [p_0, p_1, ..., p_{P-1}]   (p_0 < p_1 < ... < p_{P-1})
```

For the demo, `P = 64`.

### 3.2 Capped Cumulative Demand Vector (per bidder)

Bidder `i` with bid `(q_i, price_i)` and public cap `K` constructs a plaintext
vector of length `N = 2048`:

```
clamped_qty = min(q_i, K)
v_i[p] = clamped_qty    if price_ladder[p] <= price_i
v_i[p] = 0              if price_ladder[p] > price_i
        (slots p >= P are always 0)
```

The clamping happens in plaintext before encryption. This ensures the
aggregate demand curve accurately reflects only valid (capped) demand.

### 3.3 Comparison: M1 vs M3

| Feature | M1 (Uniform-Price) | M3 (Capped Token Sale) |
|---------|--------------------|------------------------|
| Unit | Arbitrary quantity | Discrete Lots (e.g., 100 tokens) |
| Max Quantity | Limited by `t/2` only | Public cap `K` per bidder |
| Cap Enforcement | None | Client-side (at encoding time) |
| Phases | Single-phase settlement | Commitment → Settlement |
| Collateral | Not specified | Max-price × requested_lots |
| Focus | General market clearing | Fairness and anti-whale protection |

## 4. FHE Circuit Analysis

### 4.1 Operations Required

| Phase | Operation | FHE Cost | Depth |
|-------|-----------|----------|-------|
| Encoding | `min(q_i, K)` + step function | None | 0 |
| Encryption | `pk.encrypt(v_i)` | 1 encryption/bidder | 0 |
| Accumulation | `V = Σ v_i` | n-1 ct additions | 0 |
| Masking | `V_masked = V × slot_mask` | 1 ct×pt multiply | 0 |
| Threshold decrypt | Decrypt `V_masked` | Standard protocol | — |
| Clearing price | Plaintext search on `V` | None | 0 |
| Allocation prep | Masking and per-bidder decrypt | ct×pt multiplies | 0 |

**Total multiplicative depth: 0.**

### 4.2 Noise Budget

With `n = 10` bidders and 6x62-bit moduli, the noise growth is negligible.
The system can comfortably handle thousands of additions.

### 4.3 Plaintext Range Constraint

The aggregate demand at any price level must satisfy:

```
V[p] = Σ clamped_qty_i < t/2 = 6144
```

With `n` bidders and cap `K`, we must ensure `n × K < 6144`.
For the demo: `n = 10`, `K = 500` → `max_demand = 5000 < 6144`. ✓

## 5. Protocol Flow

The protocol operates in two distinct phases to ensure commitment integrity.

### Phase 1: Commitment Phase
1. **Public Parameters**: Committee publishes `price_ladder`, `lot_size`, `cap_K`, `total_supply_lots`, and `joint_pk`.
2. **Bid Submission**:
   - Bidders choose `(q_i, price_i)`.
   - Bidders compute `v_i` (clamping `q_i` to `K`) and encrypt it.
   - Bidders lock collateral equal to `max_price_i × clamped_qty_i`.
   - Encrypted bids are submitted and fixed.

### Phase 2: Settlement Phase
1. **Accumulation**: Aggregator sums all encrypted `v_i` to get `V`.
2. **Price Discovery**: Committee threshold-decrypts `V`. Search for clearing price `P*` where `demand >= total_supply_lots`.
3. **Allocation Extraction**:
   - For each bidder, the committee masks `v_i` to extract slots at `P*` and `P* + 1`.
   - Threshold-decrypt masked vectors.
4. **Finalization**:
   - Compute exact lot allocations via largest-remainder rounding.
   - **Payment**: `clearing_price × allocated_lots`.
   - **Refund**: `collateral - payment`.
   - Distribute tokens and release refunds.

## 6. Edge Cases

| Case | Handling |
|------|----------|
| Bidder submits `q_i > K` | Encoder clamps to `K`. FHE circuit sees `K`. |
| Total demand < supply | All bidders get their requested lots. Clear at `price_ladder[0]`. |
| All bidders bid at same price | All are marginal. Pro-rata distribution of `total_supply_lots`. |
| Zero-lot bid | Valid. Contributes zero to demand curve. |
| `K = 1` | Minimum participation sale. Each bidder gets at most 1 lot. |
| Vesting Schedule | Handled off-chain as metadata. FHE only determines allocation. |

## 7. Implementation Plan

### Phase 1: Crate scaffolding
- Create `examples/token-sale/Cargo.toml` depending on `auction_bitplane_example`.
- Setup project structure.

**QA**: `cargo check` passes.

### Phase 2: Core library (`src/lib.rs`)
1. **`SaleConfig`**: Struct holding `lot_size`, `cap_K`, `total_supply_lots`, `price_ladder`, and `vesting_metadata`.
2. **`encode_capped_demand_vector`**: Implements `min(q_i, K)` clamping and step-function generation.
3. **`compute_settlement`**: Functions for `compute_payment` and `compute_refund` based on clearing results.
4. **Shared logic**: Re-export accumulation and threshold decryption helpers from shared infra.

**QA**: Unit tests for `encode_capped_demand_vector` verify that any input `> K` results in a vector for `K`.

### Phase 3: Demo binary (`src/bin/demo.rs`)
- 10 bidders.
- At least one bidder tries to exceed `K` (verify it's clamped).
- Simulate Commitment and Settlement phases.
- Print cleared price, individual lot allocations, and refund amounts.

**QA**: `cargo run --bin demo` shows successful verification against plaintext shadow bids.

### Phase 4: Tests
- **Cap Test**: Verify `encode_capped_demand_vector(qty=1000, cap=500)` equals `encode_capped_demand_vector(qty=500, cap=500)`.
- **Rounding Test**: Verify largest-remainder rounding for discrete lots.
- **Collateral Test**: Verify `refund = collateral - (clearing_price * allocation)` holds for all bidders.

**QA**: `cargo test` passes with 100% coverage of allocation logic.
