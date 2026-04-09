# Implementation Plan: Bit-Plane Auction Demo

This project implements a new auction architecture based on a bit-plane tallying approach to compare the efficiency of rotation-free FH-encryption against the traditional rotation-based prefix-scan.

## Goal
To demonstrate that a bit-plane tallying approach can achieve $O(1)$ multiplicative depth and eliminate the need for expensive column rotations, while maintaining correctness through hierarchical tie-breaking in plaintext.

## Architecture: Bit-Plane Tallying
1. **Bitwise Signals**: For each bit $j$, compute $Gt_{i,j}$ (bidder $i$ wins bit $j$) and $Eq_{i,j}$ (bidder $i$ ties bit $j$) in parallel.
2. **Tally Matrix**: Accumulate these signals into an $N \times B$ matrix of ciphertexts (one per bidder per bit).
3. **Plaintext Ranking**: Decrypt the matrix and use hierarchical tie-breaking (MSB $\rightarrow$ LSB) to identify the winner.

## Task List

### 1. Scaffolding
- [ ] Create directory `examples/auction-bitplane`.
- [ ] Copy template files from `examples/auction`.

### 2. Core Library (`src/lib.rs`)
- [ ] Implement `generate_bitwise_signals`: Returns $Gt$ and $Eq$ signals for each bit.
- [ ] Implement `accumulate_tallies`: Aggregates signals into an $N \times B$ matrix.
- [ ] Implement `rank_bidders_from_tallies`: Hierarchical tie-breaking in plaintext.

### 3. Server & Client
- [ ] Update `server/src/auction.rs` to handle bit-plane state.
- [ ] Update `server/src/routes.rs` to implement the bit-plane `close` flow.
- [ ] Ensure WASM client compatibility.

### 4. Benchmarking
- [ ] Implement comparison script for:
    - Execution time (Server-side).
    - Memory footprint.
    - Correctness verification.