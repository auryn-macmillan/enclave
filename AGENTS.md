# AGENTS.md

## Project: Batch Auction Examples on Threshold FHE

This repo contains The Interfold (formerly Enclave), a protocol for confidential coordination using FHE + ZKP + MPC. The existing `examples/auction-bitplane/` implements a sealed-bid Vickrey auction on threshold BFV.

The current goal is to build a family of **batch auction** examples that demonstrate increasingly complex confidential market mechanisms, all built on the same threshold BFV infrastructure.

## Existing infrastructure (do not rewrite)

The following are already implemented and working on the `feat/eval-key` branch:

- **Distributed DKG**: 2-of-3 committee, additive BFV secret key shares, Shamir threshold shares for decryption
- **Distributed eval-key MPC**: Galois keys (11 rotations) + relinearization key, never reconstructs full secret key
- **BFV SIMD batching**: degree 2048 = 2048 slots, two rows of 1024, column rotations + row swap
- **Bitplane encoding**: one slot per bidder, 64 bitplanes (MSB-first), ct x ct multiply + relin (depth 1)
- **Multi-coefficient poly encoding**: SLOT_WIDTH=16 coefficients per price level, `Encoding::poly()`, addition-only aggregation (depth 0)
- **Threshold decryption**: 2-of-3 with smudging noise (80-bit statistical security)
- **ZK proof circuits**: C8 (galois share), C9 (relin round1), C10 (relin round2) — all prove+verify working

Key files:
- `examples/auction-bitplane/src/lib.rs` — Vickrey auction: params, DKG, encoding, tally, decryption, ranking (~1200 lines)
- `examples/auction-bitplane/src/bin/demo.rs` — 10-bidder demo binary (~195 lines)
- `crates/trbfv/src/distributed_eval_key.rs` — Distributed eval-key generation helpers
- `EVAL_KEY_MPC_DESIGN.md` — Design spec for the distributed eval-key MPC protocol

BFV parameters (Vickrey demo): N=2048, t=12289, 6x62-bit moduli, depth budget for 1 multiply + rotations + relin.

## Multi-coefficient polynomial encoding

The batch auction examples use a high-throughput encoding scheme that bypasses the depth costs of SIMD multiplications.

- Each logical price-level slot spans W=16 polynomial coefficients.
- Each coefficient holds one bit of the quantity's binary representation.
- Uses `Encoding::poly()` (raw polynomial coefficients) instead of `Encoding::simd()` (NTT slots).
- With N=2048 and W=16: 128 max price levels (demos use 64).
- Plaintext modulus constraint: `t > z` (number of bidders), NOT `t > aggregate_demand`.
- No carry propagation needed, as counts at each bit position are independent.
- All 4 batch auction examples use this encoding; the Vickrey bitplane demo uses the original SIMD encoding.

CRITICAL: BFV plaintext×ciphertext multiplication under poly encoding is polynomial convolution, NOT coefficient-wise. Mask-multiply for selective decryption does not work. Instead, full bidder ciphertexts are threshold-decrypted and only the needed coefficient blocks are read.

## Milestone roadmap

### M1: Uniform-price batch auction
**Status**: Complete — `examples/batch-auction-uniform/`
**Goal**: Sealed-bid uniform-price auction where all winning bidders pay the same clearing price.

Bidders submit encrypted (quantity, price) pairs. A fixed supply is known publicly. The FHE program determines the clearing price (highest price at which total demanded quantity >= supply), fills winning bids, and pro-rata allocates at the marginal price. Only the clearing price and per-bidder allocations are decrypted — individual bids are never revealed.

Uses cumulative demand vectors with multi-coefficient poly encoding.

### M2: Frequent batch auction (FBA)
**Status**: Complete — `examples/batch-auction-fba/`
**Goal**: Periodic batched order matching at a single clearing price per time window.

Extends M1 with time-window semantics. Orders accumulate in encrypted form during a batch interval, then are matched simultaneously. Prevents front-running by design — no order has timing priority.

Uses hybrid carry-forward with direct cumulative aggregation.

### M3: Token sale / fair launch
**Status**: Complete — `examples/token-sale/`
**Goal**: Fixed token supply, bidders submit (quantity, max-price) pairs, clearing price determined by demand curve intersection.

Similar to M1 but with token-sale-specific semantics: commitment periods, vesting schedules, and fairness guarantees. May require different encoding to handle token denomination constraints.

### M4: DEX-style batch settlement (CoW Protocol / combinatorial)
**Status**: Complete (single-pair precursor) — `examples/batch-exchange/`
**Goal**: Multiple trading pairs, orders matched in batches with uniform clearing prices per pair.

The most complex variant. Requires solving a combinatorial optimization (order matching across pairs) under FHE. Likely needs novel circuit design for the matching engine. Inspired by CoW Protocol's batch auction mechanism.

## Security / scope guardrails

- Never reconstruct the full joint BFV secret key
- All new examples must use the distributed DKG + eval-key infrastructure (not shortcuts)
- Do not modify the core `crates/trbfv/` or `crates/keyshare/` plumbing unless strictly necessary
- New examples should be self-contained under `examples/` with their own `Cargo.toml`
- Threshold decryption must include smudging noise — no unprotected decryption
- If BFV parameter changes are needed (larger degree, more moduli), document why and keep the Vickrey demo working

## Implementation approach

Each milestone should:
1. Start with a design document analyzing the FHE circuit requirements (depth, rotations, encoding)
2. Implement as a new example crate (e.g., `examples/batch-auction-uniform/`)
3. Include a demo binary with shadow plaintext verification (like the Vickrey demo)
4. Reuse the DKG + eval-key infrastructure from `auction-bitplane` (extract shared code if needed)
5. Include unit tests for encoding, FHE operations, and ranking/allocation logic

## Git / commit style

Preferred commit style: `feat:`, `fix:`, `docs:`, `chore:`

Git author:
- `Auryn`
- `auryn@users.noreply.github.com`

## Workflow expectations

- Read the existing Vickrey demo thoroughly before designing new auctions
- Produce a concrete design (encoding scheme, FHE circuit, depth analysis) before writing code
- Validate with tests as changes land
- Do not commit unless explicitly requested