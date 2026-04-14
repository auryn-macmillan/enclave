# Uniform-Price Batch Auction — FHE Circuit Design

> **Milestone**: M1 (see `AGENTS.md`)
> **Status**: Design complete, implemented
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

Bidder `i` with bid `(q_i, price_i)` constructs a plaintext vector over
`N = 2048` SIMD slots. Each price level `p` spans `SLOT_WIDTH = 16`
consecutive SIMD slots. Each slot holds one bit of the quantity `q_i`'s
binary representation.

```
slot[p*16 + j] = bit_j(q_i)    if price_ladder[p] <= price_i
slot[p*16 + j] = 0             if price_ladder[p] > price_i
        (for j in 0..16; levels p >= P are always 0)
```

This is a bit-decomposed SIMD step function. The bidder computes this
**in plaintext before encryption** using `Encoding::simd()`.

**Example**: Price ladder `[10, 20, 30, 40, 50]`, bidder bids
`(qty=100, price=30)`:
100 = `0b0000000001100100`.

The SIMD slot blocks for `p=10, 20, 30` (indices `160..175`, `320..335`,
`480..495`) will all contain `[0,0,1,0,0,1,1,0, 0,0,0,0,0,0,0,0]`.
Blocks for `p=40, 50` will contain all zeros.

### 3.3 Encryption

Each bidder encrypts their plaintext vector as a single BFV ciphertext using
`Encoding::simd()`. **One ciphertext per bidder.**

### 3.4 Accumulation

The aggregator sums all bidder ciphertexts:

```
V = Σ_i v_i
```

This is `n_bidders - 1` homomorphic additions (depth 0). The result `V`
is a ciphertext where each block of 16 SIMD slots contains the bitwise sum
of quantities at that price level. Summing bit-positions independently
avoids carry propagation during FHE execution.

## 4. FHE Circuit Analysis

### 4.1 Operations Required

| Phase | Operation | FHE Cost | Depth |
|-------|-----------|----------|-------|
| Encoding | Client-side plaintext construction | None | 0 |
| Encryption | `pk.encrypt(v_i)` | 1 encryption/bidder | 0 |
| Accumulation | `V = Σ v_i` | n-1 ct additions | 0 |
| Masking | `v_i_masked = v_i × mask_i` | 1 ct×ct multiply + relin | 1 |
| Threshold decrypt | Decrypt masked ciphertext | Standard protocol | — |
| Clearing price | Plaintext search on `V` | None (plaintext) | 0 |
| Allocation prep | See §6 | ct×ct mask-multiplies | 1 |

**Total multiplicative depth: 0 for core demand-curve computation; 1 for per-bidder masked extraction.**

The depth-1 budget is **not consumed** by the core demand-curve
computation. The depth-1 multiply is used for per-bidder masked
allocation extraction (see §6).

### 4.2 Rotation Requirements

The core accumulation (addition of ciphertexts) requires **no rotations**.
Galois keys are needed only if we compute slot-wise reductions (e.g.,
summing adjacent slots for marginal-quantity extraction).

For the basic protocol, the existing 11 column-rotation + row-swap Galois
keys are sufficient. This is a bonus — the circuit is
simpler than Vickrey.

### 4.3 Noise Budget

Each ct addition grows noise additively. With `n` bidders:
- Fresh ciphertext noise: σ
- After `n-1` additions: ~n·σ
- With 6×62-bit moduli (372-bit total), noise budget is ~330 bits
- Each addition costs ~1 bit, so we can handle thousands of bidders
- The mask-multiply + relin costs a few more bits but is negligible

**Verdict**: Current parameters handle up to ~2048 bidders with margin.

### 4.4 Plaintext Range Constraint

BFV arithmetic is mod `t = 12289`. The cumulative demand at any price
level must satisfy:

```
count_at_any_bit_position < t/2 = 6144
```

Since each bidder contributes 0 or 1 to a specific bit position, the
constraint simplifies to `number_of_bidders < 6144`. With `t = 12289`
and 10 bidders in the demo, this is trivially satisfied.

This `t > z` style constraint comes from the bit-decomposition itself, not
from the choice of plaintext embedding domain. Under SIMD encoding, each
slot at bit-position `j` counts how many bidders contributed a `1` at that
bit, so `Σq_i` may exceed `t` as long as the per-bit bidder count stays
below `t/2`.

### 4.5 Parameter Sufficiency

| Parameter | Current | Needed | Verdict |
|-----------|---------|--------|---------|
| N (degree) | 2048 | 2048 | Sufficient (128 max price levels with SLOT_WIDTH=16) |
| t (plaintext mod) | 12289 | 12289 | Sufficient (z < 6144) |
| Moduli | 6×62-bit | 6×62-bit | Sufficient (depth 0, huge noise margin) |
| Galois keys | 11 rotations | 0–11 | Sufficient (unused) |
| Relin key | 1 | 0–1 | Sufficient (unused) |

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
The bidder's SIMD slot block at price index `k+1` (one above clearing)
gives their strict-winner quantity directly. Under `Encoding::simd()`, the
committee can isolate that block with an encrypted mask because ct×ct
multiplication is Hadamard (slot-wise):

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

**Mode A: Exact settlement (decrypt masked SIMD slot blocks)**

1. From the decrypted demand curve, compute `P*`, `D_strict`, `Q_marginal`, `R`.
2. For each bidder ciphertext `v_i`, the committee encrypts a mask with 1s
   at the target SIMD slots for blocks `k` and `k+1`, and 0s elsewhere.
3. Compute `v_i_masked = v_i × mask_i`, relinearize, and threshold-decrypt
   only the masked ciphertext.
4. Extract `strict_fill_i` from the SIMD slot block at `k+1` and
   `marginal_qty_i` by subtracting the decoded block at `k+1` from the
   decoded block at `k`.
5. Compute exact pro-rata in plaintext with deterministic rounding.

**Privacy note**: Under SIMD encoding, ct×ct multiplication is Hadamard
(slot-wise), so an encrypted mask cleanly zeroes all non-target slots.
Only the selected SIMD slot blocks are revealed during threshold
decryption; the rest of each bidder's cumulative demand vector remains
hidden.

**Mode B: Private settlement**

The committee encrypts a mask,
computes a ct×ct Hadamard product, relinearizes, and threshold-decrypts only
the masked SIMD slots needed for settlement. This
improves privacy relative to full per-bidder decryption because only the
selected slots are revealed, not the bidder's full demand vector. This is the
implemented approach for per-bidder extraction.

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
│              │  7. Extract clearing price index k
│              │  8. For each bidder: encrypt mask for SIMD slot blocks
│              │     k and k+1, multiply, relin, threshold-decrypt masked slots
│              │  9. Compute final allocations (exact pro-rata)
└─────────────┘
```

## 8. Comparison with Vickrey Demo

| Aspect | Vickrey | Uniform-Price Batch |
|--------|---------|---------------------|
| Bid type | Single scalar (price) | (quantity, price) pair |
| Encoding | 64 bitplane ciphertexts/bidder | 1 cumulative-demand ciphertext/bidder |
| FHE computation | Tally per bitplane (depth 1) | Sum across bidders (depth 0) |
| Rotations used | 11 per bitplane × 64 = 704 | 0 for core computation (SIMD slot blocks; no reductions needed) |
| Relin used | Yes (64 relinearizations) | No for core sum; yes for per-bidder masked extraction |
| Depth consumed | 1 | 0 for core computation; 1 with per-bidder masked extraction |
| Decryption surface | 64 tally ciphertexts + winner's bid | 1 aggregate ciphertext + n masked bidder ciphertexts |
| Privacy | Individual bids never decrypted | Clearing price + allocations; only masked SIMD slot blocks are revealed |
| Complexity | O(BID_BITS × n) rotations | O(n) additions |

## 9. Ciphertext Count and Performance

| Component | Count | Notes |
|-----------|-------|-------|
| Bidder ciphertexts | n | One per bidder |
| Aggregate demand | 1 | Sum of all bidder ciphertexts |
| **Total threshold decryptions** | **1 + n** | Demand curve + masked per-bidder slot-block ciphertexts |

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
| Bit-position wraps mod t | MUST enforce `number_of_bidders < t/2 = 6144` |
| Equal fractional remainders | Tiebreak by lower SIMD slot block index (see §6.2) |
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
- Enforce `number_of_bidders < t/2 = 6144` (already satisfied by the demo)
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
