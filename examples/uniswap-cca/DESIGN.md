# Uniswap CCA — Sealed-Bid FHE Replacement (Design A)

> **Milestone**: M5 (Sealed-Bid Continuous Clearing)
> **Status**: Design complete
> **Infrastructure**: Threshold BFV (2-of-3 committee), distributed DKG + eval-key MPC

## 1. Problem Statement

The Uniswap Continuous Clearing Auction (CCA) accepts public `(budget, max_price)` bids. This transparency reveals bidder intent, enabling front-running and strategic manipulation. Replace these public bids with FHE-encrypted commitments using threshold BFV. The mechanism must preserve continuous clearing semantics: per-block token releases, uniform clearing prices, and pro-rata marginal allocations, while keeping individual bidder parameters private until settlement.

## 2. Key Insight: Offchain FHE + Onchain Settlement

Bidders submit encrypted demand vectors offchain to a ciphernode committee. The committee aggregates these vectors via homomorphic addition (depth 0) and performs selective threshold decryption to discover the clearing price for each block. Only the final clearing price, per-bidder allocations, and aggregate net flow (the pool-level settlement quantity) are posted onchain as settlement data. Validation hooks in the CCA contract verify ZK proofs of bid validity (e.g., budget matches locked collateral) without revealing the bid's internal values.

## 3. Encoding Scheme

Uses SIMD bit-decomposed encoding with `N=8192` (8192 slots, two rows of 4096). Each logical price level spans `SLOT_WIDTH=16` consecutive SIMD slots. Each slot holds one bit of the quantity's binary representation.

* **Price Ladder**: 512 max price levels (8192 / 16 = 512).
* **Demand Vector**: Each bidder encrypts a step function where `slots[p] = bit_decomposed(qty)` for all `p <= max_price`.
* **Plaintext Modulus**: `t = 65537` (Fermat prime; SIMD-compatible since `2N | (t-1)`).
* **Constraint**: `t > number_of_bidders`. Bits are independent and do not carry over between SIMD slots.

## 4. FHE Circuit Analysis

| Phase | Operation | FHE Cost | Depth |
|-------|-----------|----------|-------|
| Accumulation | Homomorphic sum of ciphertexts | n-1 additions | 0 |
| Clearing Search | Selective aggregate bucket reveal | Binary search (decryptions) | 0 |
| Masking | `V_agg × slot_mask` | 1 ct×pt multiply | 0 |
| Allocation Extraction | `V_bidder × price_mask` | 1 ct×pt multiply | 0 |

**Total multiplicative depth: 0 for the core pipeline.** The circuit utilizes 3 QIs for optimal noise management during aggregation.
Threshold decryption uses smudging noise for 80-bit statistical security, consistent with the 2-of-3 committee infrastructure.
Note: `ct×ct` multiplications carry depth 1; none are used in the core pipeline above (depth 0 throughout).

## 5. Onchain/Offchain Boundary

| Component | Onchain (Ethereum) | Offchain (Ciphernodes) |
|-----------|--------------------|------------------------|
| Bidding | Bid commitment (hash), Collateral lock | Encrypted ciphertext storage |
| Validation | ZK proof verification (IValidationHook) | ZK proof generation |
| Clearing | Clearing price update, Settlement | Homomorphic aggregation, Search |
| Settlement | Token distribution, Refunds | Threshold decryption shares |
| Graduation | Seed v4 pool (LBP Strategy) | Final price handoff |

## 6. Protocol Flow

1. **Setup**: Committee runs DKG and publishes joint public key onchain.
2. **Bidding**: Bidders encrypt bids, submit commitments + collateral onchain, and send ciphertexts to the committee.
3. **Clearing**: For each block, the committee aggregates ciphertexts and searches for the clearing price via selective decryption of the aggregate curve.
4. **Allocation Decryption**: For each bidder, the committee multiplies the encrypted demand vector by a mask selecting only the clearing price level, then threshold-decrypts with smudging noise (80-bit statistical security) to obtain the individual allocation. Only allocations at the clearing price level are decrypted.
5. **Settlement**: Committee posts the clearing price and per-bidder allocations onchain. The contract executes token distribution and collateral refunds.
6. **Graduation**: LBP Strategy seeds v4 pool at discovered price.

## 7. What Is Revealed vs What Stays Hidden

| Data | Status | Why? |
|------|--------|------|
| Clearing price | Revealed | Required for onchain settlement |
| Aggregate demand at clearing | Revealed | Needed to verify clearing condition |
| Per-bidder allocation | Revealed | Required to distribute tokens |
| Individual max price | Hidden | Never decrypted unless bidder is marginal |
| Individual budget | Hidden | Only total allocation is revealed |
| Demand at non-clearing levels | Hidden | Zeroed by plaintext masks before decryption |

## 8. Edge Cases

| Case | Handling |
|------|----------|
| Insufficient demand | No clearing found; clearing price remains at floor |
| Single bidder | Fills up to available supply at their price |
| All bids at same price | All are marginal; pro-rata distribution applied |
| Supply exactly met | Clearing at the exact intersection; no rationing |
| Committee offline | 2-of-3 threshold allows clearing to proceed with 1 failure |
| Late bid submission | Rejected by onchain commitment timestamp |
| Graduation criteria | CCA transitions to v4 pool at final clearing price |

## 9. Latency Analysis

* **Aggregation**: Linear in the number of bidders (additions only); completes in <1s for thousands of bids.
* **Clearing Search**: Logarithmic decryptions (binary search); ~5-10 threshold decryptions per block.
* **Total block time**: Ethereum (12s) is sufficient for FHE processing. Ciphernodes can operate in parallel to batch windows of 6-60s if needed.

## 10. Lifecycle Bridge

Tokens launched via Design A graduate to a Uniswap v4 pool. The `LiquidityLauncher` seeds the pool at the final discovered clearing price. Ongoing trading in the v4 pool can then transition to Design C (Encrypted Hook), utilizing the same committee infrastructure and public key for consistent privacy across the token lifecycle. Reference `examples/uniswap-v4-hook/` for the post-graduation trading environment.

## 11. BFV Parameters

| Parameter | Value |
|-----------|-------|
| N (degree) | 8192 |
| t (plaintext mod) | 65537 |
| Moduli (QIs) | 3 |
| SIMD slots | 8192 (two rows of 4096) |
| SLOT_WIDTH | 16 |
| Max Price Levels | 512 |
| Available Depth Budget | ~2-3 multiplications (circuit uses 0) |
