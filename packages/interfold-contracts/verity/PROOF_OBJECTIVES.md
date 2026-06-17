# Proof Objectives — Interfold Formal Verification with Verity

**Defined before implementation.** Each objective is a concrete, provable
property with a clear success criterion. Properties that cannot be proved in
Verity are explicitly marked as trust boundaries.

## InterfoldToken (token/InterfoldToken.sol)

### In scope

| ID      | Property                                                                                                                                              | Type                 | Solidity Source |
| ------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------- | --------------- |
| INTF-P1 | `mintAllocation` reverts when `totalMinted + amount > MAX_SUPPLY`                                                                                     | Safety / revert      | L152            |
| INTF-P2 | On success, `totalMinted' = totalMinted + amount` and `balances[recipient]' = balances[recipient] + amount` and `totalSupply' = totalSupply + amount` | Accounting           | L154-155        |
| INTF-P3 | `mintAllocation` reverts when caller lacks `MINTER_ROLE`                                                                                              | Access control       | L148            |
| INTF-P4 | `disableTransferRestrictions` sets `transfersRestricted` from `true` to `false`; idempotent when already `false`                                      | One-way switch       | L205-207        |
| INTF-P5 | `disableTransferRestrictions` reverts when caller lacks `DEFAULT_ADMIN_ROLE`                                                                          | Access control       | L203            |
| INTF-P6 | `_update` reverts when `transfersRestricted && from ≠ 0 && to ≠ 0 && !whitelisted[from] && !whitelisted[to]`                                          | Transfer restriction | L261-264        |
| INTF-P7 | `_update` does NOT revert on restriction check when `from == 0` (mint) or `to == 0` (burn)                                                            | Mint/burn exemption  | L261            |
| INTF-P8 | `toggleTransferWhitelist` flips `transferWhitelisted[account]`                                                                                        | Whitelist management | L220-221        |
| INTF-P9 | `toggleTransferWhitelist` reverts when caller lacks `WHITELIST_ROLE`                                                                                  | Access control       | L219            |

### Out of scope (trust boundaries)

- `ERC20Votes` checkpoint logic (voting power) — not modeled
- `ERC20Permit` (EIP-2612) — not modeled
- `Ownable2Step` ownership transfer with role sync — modeled as direct role
  grant/revoke
- `keccak256` for role IDs — role constants are opaque `Uint256` values

### Role system model

Solidity uses `AccessControl` with `mapping(bytes32 => RoleData)` where
`RoleData` has `mapping(address => bool) members`. We model this faithfully as:

- `roleMembers : StorageSlot (Uint256 → Address → Bool)` (storageMap2)
- `DEFAULT_ADMIN_ROLE : Uint256 := 0` (Solidity: `bytes32(0)`)
- `MINTER_ROLE : Uint256 := <opaque>` (Solidity: `keccak256("MINTER_ROLE")`)
- `WHITELIST_ROLE : Uint256 := <opaque>` (Solidity:
  `keccak256("WHITELIST_ROLE")`)

The `onlyRole(role)` guard checks `roleMembers[role][msg.sender]`.

---

## InterfoldTicketToken (token/InterfoldTicketToken.sol)

### In scope

| ID      | Property                                                                                                                                       | Type                 | Solidity Source |
| ------- | ---------------------------------------------------------------------------------------------------------------------------------------------- | -------------------- | --------------- |
| ITK-P1  | `depositFor`, `depositFrom`, `withdrawTo`, `burnTickets`, `payout` all revert when `msg.sender ≠ registry`                                     | Access control       | L151-154        |
| ITK-P2  | `burnTickets(op, amount)` increments `payableBalance` by `amount`, decrements `balances[op]` by `amount`, decrements `totalSupply` by `amount` | Accounting           | L320-321        |
| ITK-P3  | `payout` reverts when `amount > payableBalance`                                                                                                | Safety / bounds      | L331            |
| ITK-P4  | On success, `payout` decrements `payableBalance` by `amount` and `underlyingBal` by `amount`                                                   | Accounting           | L332-333        |
| ITK-P5  | `_update` reverts when `from ≠ 0 && to ≠ 0`                                                                                                    | Non-transferability  | L389-390        |
| ITK-P6  | `approve` always reverts                                                                                                                       | Disabled flow        | L362-363        |
| ITK-P7  | `permit` always reverts                                                                                                                        | Disabled flow        | L377-378        |
| ITK-P8  | `delegate` reverts when `delegatee ≠ msg.sender`                                                                                               | Self-delegation only | L401            |
| ITK-P9  | `activateRegistryChange` reverts when `block.timestamp < pendingRegistryActivationTime`                                                        | Timelock             | L222-223        |
| ITK-P10 | `lockRegistry` sets `registryLocked` from `false` to `true`; reverts when already `true`                                                       | One-way switch       | L199-200        |
| ITK-P11 | `setRegistry` reverts when `registryLocked == true`                                                                                            | Lock enforcement     | L188            |
| ITK-P12 | `requestRegistryChange` reverts when `registryLocked == false`                                                                                 | Lock enforcement     | L208            |

### Out of scope (trust boundaries)

- `SafeERC20.safeTransferFrom` / `safeTransfer` — external ERC20 behavior is an
  oracle
- Fee-on-transfer delta measurement (`balanceBefore`/`balanceAfter`) — modeled
  as exact amount (oracle returns `amount`)
- `ERC20Votes` delegation checkpoint logic — not modeled
- `ERC20Wrapper` base implementation — modeled directly

### Peg invariant

The 1:1 peg (`underlyingBal == totalSupply + payableBalance`) is preserved by:

- `burnTickets`: `totalSupply -= amount`, `payableBalance += amount`
  (underlyingBal unchanged) ✓
- `payout`: `payableBalance -= amount`, `underlyingBal -= amount` (totalSupply
  unchanged) ✓
- `depositFor`/`depositFrom`: `totalSupply += received`,
  `underlyingBal += received` (modeled as exact) ✓
- `withdrawTo`: `totalSupply -= amount`, `underlyingBal -= amount` ✓

We prove `ITK-PEG`: the peg invariant
(`underlyingBal == totalSupply + payableBalance`) is preserved by each
individual operation.

> **Correction**: An earlier version of this document stated the peg as
> `totalSupply == underlyingBal + payableBalance`. This equation is
> mathematically incorrect — it does not hold for `burnTickets` or `payout`. The
> correct accounting equation is `underlyingBal == totalSupply + payableBalance`
> (Assets = Equity + Liabilities).

---

## BondingRegistry (registry/BondingRegistry.sol)

### In scope

| ID    | Property                                                                               | Type                 | Solidity Source |
| ----- | -------------------------------------------------------------------------------------- | -------------------- | --------------- |
| BR-P1 | `slashTicketBalance` and `slashLicenseBond` revert when `msg.sender ≠ slashingManager` | Access control       | L158-161        |
| BR-P2 | `registerOperator` reverts when `operators[msg.sender].registered == true`             | Registration guard   | L329            |
| BR-P3 | `registerOperator` reverts when `licenseBond < licenseRequiredBond`                    | Registration guard   | L330-333        |
| BR-P4 | `registerOperator` clears previous exit request before checking preconditions          | State clearing       | L320-323        |
| BR-P5 | `deregisterOperator` reverts when `!registered`                                        | Deregistration guard | L346            |
| BR-P6 | `bondLicense` increments `licenseBond[op]` by received amount                          | Accounting           | L454            |
| BR-P7 | `unbondLicense` reverts when `licenseBond[op] < amount`                                | Bounds check         | L471-474        |
| BR-P8 | `unbondLicense` decrements `licenseBond[op]` by `amount` on success                    | Accounting           | L476            |
| BR-P9 | `deregisterOperator` sets `exitUnlocksAt = block.timestamp + exitDelay`                | Exit delay           | L361            |

### Out of scope (trust boundaries)

- External calls to `CiphernodeRegistry.addCiphernode`/`removeCiphernode` —
  oracle
- External calls to `SlashingManager.isBanned`/`hasOpenLaneBProposal` — oracle
- `InterfoldTicketToken.depositFrom`/`burnTickets`/`payout` — oracle (verified
  separately)
- `SafeERC20.safeTransferFrom` for license token — oracle
- `ExitQueueLib` internal queue mechanics — modeled as simplified per-operator
  state
- Global balance conservation (requires whole-mapping iteration) — assumed,
  verified per-transition

### Per-operator state model

The Solidity uses a
`struct Operator { uint256 licenseBond; uint64 exitUnlocksAt; bool registered; bool exitRequested; bool active; }`
stored in a mapping. We model each field as a separate storage mapping:

- `licenseBond : Address → Uint256`
- `exitUnlocksAt : Address → Uint256`
- `registered : Address → Bool`
- `exitRequested : Address → Bool`
- `active : Address → Bool`

This is a faithful representation — the struct fields map 1:1 to Verity
mappings.

### Important: registerOperator exit clearing

The Solidity `registerOperator` (L318-341) does:

1. If `exitRequested`, clear it (`exitRequested = false`, `exitUnlocksAt = 0`)
2. Check `!isBanned(msg.sender)` — oracle
3. Check `!registered`
4. Check `licenseBond >= licenseRequiredBond`
5. Set `registered = true`

Step 1 happens BEFORE the `noExitInProgress` modifier check is bypassed. Wait —
actually the `noExitInProgress` modifier (L169-177) checks
`exitRequested && block.timestamp < exitUnlocksAt`. If the exit is still locked,
the modifier reverts BEFORE the function body runs. So the clearing in step 1
only happens when the exit has already unlocked (modifier passes). This is
correct behavior that must be faithfully modeled.

---

## E3RefundManager (E3RefundManager.sol)

### In scope

| ID      | Property                                                                    | Type |
| ------- | --------------------------------------------------------------------------- | ---- |
| E3RM-P1 | `calculateRefund` reverts when already calculated for that E3 (idempotency) |
| E3RM-P2 | `claimRequesterRefund` reverts when already claimed (replay protection)     |
| E3RM-P3 | `escrowSlashedFunds` reverts when caller ≠ Interfold                        |
| E3RM-P4 | `calculateRefund` reverts when caller ≠ Interfold                           |
| E3RM-P5 | On success, `claimRequesterRefund` sets `claimed[e3Id][sender] = true`      |

### Out of scope

- BPS math (work allocation percentages) — requires loop over nodes, modeled as
  oracle
- Pull-payment actual ERC20 transfers — oracle

---

## SlashingManager (slashing/SlashingManager.sol)

### In scope

| ID    | Property                                                                                         | Type              |
| ----- | ------------------------------------------------------------------------------------------------ | ----------------- |
| SM-P1 | `setSlashPolicy` reverts when `ticketPenalty == 0 && licensePenalty == 0`                        | Policy validation |
| SM-P2 | `setSlashPolicy` reverts when `!requiresProof && appealWindow == 0` (Lane B needs appeal window) | Policy validation |
| SM-P3 | `executeSlash` reverts when proposal already executed                                            | Lifecycle guard   |
| SM-P4 | `executeSlash` reverts when `block.timestamp < executableAt` (appeal window active)              | Timing            |
| SM-P5 | `fileAppeal` reverts when `msg.sender ≠ proposal.operator`                                       | Access control    |
| SM-P6 | `fileAppeal` reverts when `block.timestamp >= executableAt` (window expired)                     | Timing            |
| SM-P7 | `resolveAppeal` reverts when caller lacks `GOVERNANCE_ROLE`                                      | Access control    |
| SM-P8 | `confirmBan` reverts when already banned                                                         | Idempotency       |

### Out of scope

- ECDSA signature verification (attestation evidence) — oracle
- `keccak256` for evidence hashing — axiomatized
- External calls to `BondingRegistry` for slash execution — oracle
- Proposal counter overflow — trivially prevented by Solidity 0.8 checked
  arithmetic

---

## Trust Boundaries Summary

| Boundary             | What's assumed                            | Why                                            |
| -------------------- | ----------------------------------------- | ---------------------------------------------- |
| `SafeERC20`          | Transfers succeed and move exact amounts  | OZ v5, industry standard                       |
| `keccak256`          | Collision-resistant, deterministic        | Cryptographic assumption                       |
| `ECDSA.recover`      | Returns correct signer                    | Cryptographic assumption                       |
| Cross-contract calls | Callee behaves per its own spec           | Each contract verified independently           |
| `ExitQueueLib`       | Queue operations are correct              | Modeled as simplified per-operator state       |
| `ERC20Votes`         | Checkpoint logic is correct               | Not relevant to safety properties proved       |
| Global conservation  | Per-transition correctness implies global | Requires whole-mapping iteration (unsupported) |
