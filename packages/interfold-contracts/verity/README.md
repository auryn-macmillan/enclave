# Interfold Smart Contracts — Verity Formal Verification

Formal verification of critical Interfold smart contracts using
[Verity](https://veritylang.com/), a Lean 4 embedded DSL for writing formally
verified smart contracts.

## Prerequisites

1. Install Lean 4 via [elan](https://github.com/leanprover/elan)
2. Clone Verity: `git clone https://github.com/lfglabs-dev/verity.git`
3. Build Verity: `cd verity && lake build`
4. Set `VERITY_ROOT` to point to the Verity repository

## Building

```bash
lake build                          # Verify all proofs
lake build Contracts.InterfoldToken # Build specific contract
```

## Compiling to EVM Yul

```bash
lake exe verity-compiler --contract InterfoldToken -o artifacts/yul
```

## Contracts

| Contract             | Status   | Description                                                    |
| -------------------- | -------- | -------------------------------------------------------------- |
| InterfoldToken       | Phase 1a | ERC20 governance token with mint cap and transfer restrictions |
| InterfoldTicketToken | Phase 1b | Non-transferable ERC20Votes wrapper for operator staking       |
| BondingRegistry      | Phase 2a | Operator fund custody, exit queue, slashing interface          |
| E3RefundManager      | Phase 2b | Refund distribution for failed E3 computations                 |
| SlashingManager      | Phase 2c | Fault attribution with two-lane slashing                       |

## Trust Boundaries

See `TrustBoundaries/Assumptions.lean` for documented trust assumptions.
