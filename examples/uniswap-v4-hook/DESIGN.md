# Uniswap v4 Hook (Encrypted Batch Settlement) — Design C

> **Milestone**: M4 extension — post-launch MEV protection
> **Status**: Design complete
> **Infrastructure**: Threshold BFV (2-of-3 committee), distributed DKG + eval-key MPC

## 1. Problem Statement

After a token launches (e.g., via Design A's CCA), standard trading on Uniswap v4 remains vulnerable to MEV vectors like sandwich attacks and front-running. These attacks exploit the transparency of individual transaction parameters.

This hook collects encrypted swap intents during a batch window, clears them offchain via FHE, and settles the net flow against the AMM pool. By batching trades at a single clearing price and only revealing settlement/allocation data — including the aggregate net flow — per-transaction MEV is eliminated. This design applies the Frequent Batch Auction (FBA) mechanism to the Uniswap v4 ecosystem.

## 2. Key Insight: Intent Accumulator

The v4 hook acts as an intent accumulator rather than a per-trade executor. During each batch epoch (12-60 seconds), encrypted swap intents are collected via the `beforeSwap` hook. The ciphernode committee aggregates buy and sell demand homomorphically, determines the clearing price via selective decryption, and posts a single net settlement transaction. Individual intent details (direction, quantity, limit price) are never revealed — only the clearing price, aggregate net flow, and per-user fill amounts are decrypted and posted for settlement.

## 3. Encoding Scheme

Uses a two-sided SIMD bit-decomposed encoding adapted from `examples/batch-exchange/`.

*   **Parameters**: N=8192 (8192 slots, two rows of 4096), SLOT_WIDTH=16, t=65537.
*   **Price Ladder**: 512 max price levels (8192 / 16 = 512).
*   **Vectors**: Separate cumulative demand vectors for buy intents (descending) and sell intents (ascending).
*   **Intents**: Each intent `(direction, quantity, limit_price)` is encoded as a bit-decomposed demand contribution across the appropriate price levels.
*   **Constraint**: `t > number_of_bidders`. Bits are independent and do not carry between SIMD slots.

## 4. FHE Circuit Analysis

| Phase | Operation | FHE Cost | Depth |
|-------|-----------|----------|-------|
| Accumulation | Homomorphic sum of buy/sell intents | n-1 additions | 0 |
| Curve Computation | Aggregate demand curve sum | Addition | 0 |
| Clearing Search | Selective mask-multiply + decrypt | ct×pt multiply | 0 |
| Net Flow Calc | Crossing price extraction | Threshold decryption | 0 |

The circuit finds the price where aggregate buy demand crosses aggregate sell demand. Total multiplicative depth is 0 for the core pipeline, utilizing 3 QIs for noise management.
Threshold decryption uses smudging noise for 80-bit statistical security, consistent with the 2-of-3 committee infrastructure described in the existing repo examples.
Note: `ct×ct` multiplications carry depth 1; none are used in the core pipeline above (depth 0 throughout).

## 5. Onchain/Offchain Boundary

| Component | Onchain (Uniswap v4) | Offchain (Ciphernodes) |
|-----------|----------------------|------------------------|
| Swap Intent | `beforeSwap` commitment, Collateral lock | Encrypted ciphertext storage |
| Aggregation | Pending intent tracking, Epoch management | Homomorphic sum of vectors |
| Clearing | Net flow settlement via `settle()` | Selective decryption, Price search |
| Accounting | PoolManager flash accounting (Deltas) | Net flow and per-user fill computation |
| Distribution | Per-user token allocation | Threshold decryption of fill amounts |

## 6. Protocol Flow

1.  **Epoch Open**: Hook accepts encrypted swap intents via `beforeSwap`.
2.  **Epoch Close**: No new intents; committee begins FHE computation.
3.  **Aggregation**: Homomorphic sum of buy and sell demand vectors across the epoch.
4.  **Clearing**: Selective decryption to find the crossing price and compute net flow.
5.  **Settlement**: Relayer posts a single transaction to settle the net flow against the AMM pool at the clearing price.
6.  **Distribution**: Per-user allocations are distributed based on decrypted fill amounts.

## 7. v4 Hook Architecture

The hook utilizes `beforeSwap` to intercept trade requests and redirect them to the batch accumulator. The hook maintains state for pending intent commitments per epoch and an epoch counter.

Settlement uses Uniswap v4 flash accounting. The hook calculates the net delta for the pool (e.g., net buy of 100 Token A, net sell of 95 Token A results in 5 Token A net swap against the pool). The hook interacts with the PoolManager to settle these deltas in a single atomic transaction spanning multiple logical trades.

## 8. What Is Revealed vs What Stays Hidden

| Data | Status | Why? |
|------|--------|------|
| Aggregate net flow | Revealed | Required for pool settlement |
| Clearing price | Revealed | Required for user accounting |
| Per-user fill amounts | Revealed | Required for token distribution |
| Individual intent direction | Hidden | Only aggregate net flow is revealed |
| Individual limit prices | Hidden | Never decrypted unless bidder is marginal |
| Individual quantities | Hidden | Individual inputs are never revealed |
| Non-clearing demand | Hidden | Zeroed by plaintext masks |

## 9. Edge Cases

| Case | Handling |
|------|----------|
| No intents in epoch | Hook permits standard passthrough to normal AMM swap |
| Single-sided flow | Settle entire aggregate volume against AMM directly |
| Epoch timing overrun | FHE computation spans multiple blocks; subsequent intents wait |
| Committee failure | Fallback to standard v4 swap behavior (public trades) |
| Price impact limits | Hook rejects settlement if clearing price exceeds pool bounds |
| Spam intents | Minimum collateral/fee required for encrypted intent submission |

## 10. Latency Analysis

*   **Batch Window**: Target 12-60s epochs. Shorter epochs improve UX; longer epochs increase batching efficiency and MEV resistance.
*   **FHE Compute**: Aggregation (addition only) completes in under 1 second. Selective decryption (binary search over price ladder) adds ~5-10 decryption rounds per epoch.
*   **Comparison**: Standard v4 swaps execute per-transaction with full public visibility. Shutter requires ~3 min commit-reveal latency. Design C targets 12-60s batch windows, matching FHE compute time to epoch duration.

## 11. Lifecycle Bridge

Pools launched via Design A (Uniswap CCA) naturally transition to Design C. Both systems share the same committee, BFV parameters, and trust model. Once the CCA graduation seeds the v4 pool, the Design C hook is activated to protect ongoing trading. Shared ciphernode infrastructure amortizes setup and operational costs. Reference `examples/uniswap-cca/` for the launch phase details.

## 12. BFV Parameters

| Parameter | Value |
|-----------|-------|
| N (degree) | 8192 |
| t (plaintext mod) | 65537 |
| Moduli (QIs) | 3 |
| SIMD slots | 8192 (two rows of 4096) |
| SLOT_WIDTH | 16 |
| Max Price Levels | 512 |
| Available Depth Budget | ~2-3 multiplications (circuit uses 0) |

## 13. MEV Protection Properties

*   **Sandwich Attacks**: Eliminated. No single trade is exposed to front/back-running within the batch.
*   **Front-running**: Eliminated. Orders in the same epoch execute at the same clearing price.
*   **JIT Liquidity**: Timing advantage is removed as all orders are batched.
*   **Arbitrage**: Cross-epoch arbitrage remains possible but per-transaction MEV is removed.
*   **MEV Blocker**: Provides ~90% rebates post-execution via backrunning. Design C eliminates the information asymmetry that enables sandwich attacks by ensuring no intent is visible until after the epoch clears.
