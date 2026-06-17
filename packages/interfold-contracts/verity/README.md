# Interfold Smart Contracts — Verity Formal Verification

Formal verification of critical Interfold smart contracts using
[Verity](https://veritylang.com/), a Lean 4 embedded DSL for writing formally
verified smart contracts.

## Approach

Each contract is translated from Solidity into a `verity_contract` block —
Verity's canonical authoring surface that provides:

- Typed storage slots matching Solidity's layout
- EDSL functions with `require` guards, `safeAdd`/`safeSub` for checked
  arithmetic
- Compilation to EVM Yul bytecode
- Machine-checked proofs via Lean 4

**Proof objectives are defined BEFORE implementation** — see
`PROOF_OBJECTIVES.md`.

## What's Verified

| Contract             | Proof Objectives  | Key Properties                                                                                   |
| -------------------- | ----------------- | ------------------------------------------------------------------------------------------------ |
| InterfoldToken       | INTF-P1..P9       | Supply cap, mint accounting, one-way restriction switch, transfer whitelist, AccessControl roles |
| InterfoldTicketToken | ITK-P1..P12 + PEG | 1:1 peg invariant, non-transferability, onlyRegistry access, registry timelock                   |
| BondingRegistry      | BR-P1..P9         | Slashing access control, registration guards, bond accounting, exit delay                        |
| E3RefundManager      | E3RM-P1..P5       | Claim replay protection, onlyInterfold access, distribution idempotency                          |
| SlashingManager      | SM-P1..P8         | Policy validation, proposal lifecycle, appeal window, governance access                          |

## Trust Boundaries

See `PROOF_OBJECTIVES.md` § Trust Boundaries Summary. Key boundaries:

- `SafeERC20` transfers (OpenZeppelin v5)
- `keccak256` and `ECDSA.recover` (cryptographic primitives)
- Cross-contract calls (each contract verified independently)
- `ExitQueueLib` internal mechanics (simplified per-operator state)
- `ERC20Votes` checkpoint logic (not modeled)

## Building

```bash
# Prerequisites: elan (Lean 4), Foundry, solc 0.8.33+
git clone https://github.com/lfglabs-dev/verity.git
cd verity && lake build

# Build Interfold verification
lake build Contracts.InterfoldToken.Proofs.Basic
```

## Verification Checklist

```bash
# All proofs must compile with zero `sorry` admissions
lake build
grep -r "sorry" . --include="*.lean"  # must return nothing
```
