# Formal Verification Plan — Interfold Smart Contracts via Verity

## 1. Overview

Formally verify critical Interfold smart contracts using [Verity](https://veritylang.com/), a Lean 4
embedded DSL for writing formally verified smart contracts that compile to EVM bytecode.

**Key insight**: Verity is NOT a tool that runs against existing Solidity. It is a language in which
you _rewrite_ contracts and embed machine-checked proofs.

**Approach**: Translate critical contract functions from Solidity → Verity EDSL, write formal specs,
prove theorems, compile to EVM bytecode, cross-validate against existing Hardhat tests.

## 2. Contract Selection & Prioritization

### Phase 1: Token Contracts (Smallest scope, most self-contained)

| Contract                     | Lines | Why Verify                                                     | Verity Fit                                                    |
| ---------------------------- | ----- | -------------------------------------------------------------- | ------------------------------------------------------------- |
| **InterfoldToken.sol**       | 337   | ERC20 token; mint cap, transfer restrictions, governance roles | Self-contained; no external calls in core logic               |
| **InterfoldTicketToken.sol** | 459   | Non-transferable ERC20Votes wrapper; operator stake            | Self-contained wrapper; only calls registry for authorization |

### Phase 2: Fund Custody & Refunds (Medium complexity, internal accounting)

| Contract                | Lines | Why Verify                                           | Verity Fit                                                                              |
| ----------------------- | ----- | ---------------------------------------------------- | --------------------------------------------------------------------------------------- |
| **BondingRegistry.sol** | 899   | Holds operator funds; exit queue, slashing interface | Complex accounting; per-transition invariants feasible; global sums require ghost state |
| **E3RefundManager.sol** | 750   | Refund distribution; honest node rewards             | Pull-payment accounting; work-value BPS constraints                                     |

### Phase 3: Fault Attribution (Most complex, deferred if needed)

| Contract                | Lines | Why Verify                              | Verity Fit                                                    |
| ----------------------- | ----- | --------------------------------------- | ------------------------------------------------------------- |
| **SlashingManager.sol** | 876   | Slashing lifecycle; committee expulsion | Policy validation feasible; EIP-712 / ECDSA on trust boundary |

### Deferred (Not in scope for initial verification)

| Contract                                                                 | Reason                                                                                |
| ------------------------------------------------------------------------ | ------------------------------------------------------------------------------------- |
| **Interfold.sol** (1229 lines)                                           | Heavy cross-contract call surface, ZK verifier integration, 15+ external dependencies |
| **CiphernodeRegistryOwnable.sol** (1133 lines)                           | IMT operations, DKG fold attestation, sortition — significant trust boundaries        |
| **ZK Verifier contracts**                                                | Pure verification logic; model as oracle boundaries                                   |
| **Library contracts** (InterfoldPricing, CommitteeHashLib, ExitQueueLib) | Verify through their callers                                                          |

## 3. Verity Translation Approach

### Storage Mapping

```
Solidity                              →  Verity
─────────────────────────────────────────────────────────
uint256 public totalMinted;           →  totalMinted : Uint256 := slot N
mapping(address => uint256) bal;      →  bal : Address → Uint256 := slot N
mapping(address => bool) whitelist;   →  whitelist : Address → Bool := slot N
bool public transfersRestricted;      →  transfersRestricted : Bool := slot N
struct State { ... }                  →  state : StorageStruct [...] := slot N
address public owner;                 →  owner : Address := slot N
```

### Pattern Restructuring

| Solidity Pattern                          | Verity Equivalent                                                      |
| ----------------------------------------- | ---------------------------------------------------------------------- |
| `modifier onlyOwner` / `noExitInProgress` | Named `modifier` guard called at function start                        |
| `inheritance` (is X, Y)                   | Explicit composition of storage roots + guard helpers                  |
| `ReentrancyGuard`                         | `nonreentrant(lockSlot)` on external entrypoints                       |
| `initializer`                             | `initializer(initializedSlot)` bootstrap guard                         |
| Checked arithmetic (`a + b`)              | `requireSomeUint (safeAdd a b) "overflow"`                             |
| Events (`emit Transfer(...)`)             | `emitEvent "Transfer" [amount] [addressToWord from, addressToWord to]` |
| `onlyRegistry` gate                       | Modifier checking `msgSender == registryAddress`                       |

### Trust Boundaries

| Feature                                     | Trust Boundary        | Mitigation                                        |
| ------------------------------------------- | --------------------- | ------------------------------------------------- |
| `keccak256`                                 | Axiomatized primitive | Document assumption; use `--trust-report`         |
| External calls to other Interfold contracts | Not in proof model    | Model as oracle with explicit pre/post conditions |
| EIP-712 / ECDSA signatures                  | Cryptography boundary | Model signature recovery as trusted primitive     |
| OpenZeppelin libraries (SafeERC20)          | External dependency   | Trust standard OZ behavior                        |

## 4. Detailed Verification Targets

### 4.1 InterfoldToken.sol — ERC20 Governance Token

**Actual contract behavior** (verified against source at
`packages/interfold-contracts/contracts/token/InterfoldToken.sol`):

- Constructor sets `transfersRestricted = true` and whitelists `initialOwner_`
- `disableTransferRestrictions()` is a one-way switch: `true → false` (restrictions are _disabled_,
  not enabled)
- `_update(from, to, value)` enforces: if
  `transfersRestricted && from != address(0) && to != address(0)`, then
  `require(transferWhitelisted[from] || transferWhitelisted[to])` — **either** endpoint whitelisted
  suffices
- `MAX_SUPPLY = 1_200_000_000e18` (hard cap)
- `mintAllocation(to, amount, allocation)` — role-gated (MINTER_ROLE) mint
- `batchMintAllocations(address[], uint256[], string[])` — batched mint
- `toggleTransferWhitelist(address)` — flips whitelist status (WHITELIST_ROLE)
- `enableTransferWhitelist(address)` — explicitly enables whitelist (DEFAULT_ADMIN_ROLE)

**State to model:**

- `totalMinted : Uint256` — cumulative minted
- `transfersRestricted : Bool` — defaults `true`, can only become `false`
- `transferWhitelisted : Address → Bool` — whitelist mapping
- `MAX_SUPPLY : Uint256` — constant

**Invariants to prove:**

1. `totalMinted ≤ MAX_SUPPLY` — supply cap never exceeded
2. Mint: `totalMinted' = totalMinted + amount` when mint succeeds
3. `transfersRestricted` can only transition `true → false` (one-way disable)
4. When `transfersRestricted = true`, transfers between non-zero addresses require
   `whitelisted[from] || whitelisted[to]`
5. `disableTransferRestrictions` irreversibly sets `transfersRestricted = false`

**Functions to prove:**

- `mintAllocation(to, amount, allocation)` — supply cap check, totalMinted update, balance increase
- `enableTransferWhitelist(account)` / `toggleTransferWhitelist(account)` — role-gated whitelist
  changes
- `_update(from, to, value)` — transfer hook enforcing whitelist logic
- `disableTransferRestrictions` — one-way toggle: `true → false`

### 4.2 InterfoldTicketToken.sol — Non-Transferable Wrapper

**Actual contract behavior** (verified against
`packages/interfold-contracts/contracts/token/InterfoldTicketToken.sol`):

- `depositFor(to, amount)` / `depositFrom(from, amount)` — wraps underlying stablecoin 1:1; measures
  actual received (fee-on-transfer safe)
- `withdrawTo(to, amount)` — unwraps; transfers `amount` ITK → burns ITK → transfers underlying to
  `to`
- `burnTickets(from, amount)` — `onlyRegistry`; burns ITK from operator, accumulates in
  `payableBalance`
- `payout(to, amount)` — `onlyRegistry`; transfers underlying from `payableBalance`
- `_update` blocks transfers: `revert TransferNotAllowed()` if
  `from != address(0) && to != address(0)`
- `approve` / `permit` / `delegate` — all revert (disabled)
- Registry change: `setRegistry` → `lockRegistry` → `requestRegistryChange` →
  `activateRegistryChange` with `REGISTRY_CHANGE_DELAY = 1 day`

**State to model:**

- Underlying ERC20 balance vs total ITK supply (1:1 peg)
- `registry : Address` — authorized caller for mint/burn/payout
- `registryLocked : Bool` — registry pointer lock status
- `payableBalance : Uint256` — accumulated underlying from burns

**Invariants to prove:**

1. Total ITK supply == underlying balance held + payableBalance (1:1 peg)
2. `depositFor` / `depositFrom` maintain the 1:1 peg
3. Only `registry` can call `burnTickets` / `payout` (`onlyRegistry` modifier)
4. Transfers between non-zero addresses always revert (`TransferNotAllowed`)
5. `permit` always reverts (`PermitDisabled`)
6. Delegation to any address other than self reverts (`DelegationLocked`)
7. Registry change requires timelock: `activateRegistryChange` only after `REGISTRY_CHANGE_DELAY`
   from `requestRegistryChange`

**Functions to prove:**

- `depositFor(to, amount)` / `depositFrom(from, amount)` — peg maintenance
- `withdrawTo(to, amount)` — peg maintenance on withdrawal
- `burnTickets(from, amount)` — `onlyRegistry` access control, payableBalance update
- `payout(to, amount)` — `onlyRegistry` access control
- `_update` — transfer blocking
- `setRegistry` → `lockRegistry` → `requestRegistryChange` → `activateRegistryChange` →
  `cancelRegistryChange`

### 4.3 BondingRegistry.sol — Operator Fund Custody

**Actual contract behavior** (verified against
`packages/interfold-contracts/contracts/registry/BondingRegistry.sol`):

- `registerOperator()` — `noExitInProgress` guard; registers in CiphernodeRegistry
- `deregisterOperator()` — `noExitInProgress` guard; burns all tickets, queues bonds for exit,
  removes from registry
- `addTicketBalance(amount)` — transfers ITK from caller, mints ITK to operator
- `removeTicketBalance(amount)` — burns ITK, queues underlying for exit
- `bondLicense(amount)` — transfers INTF from caller, increments bond
- `unbondLicense(amount)` — queues license token for exit (timelocked)
- `claimExits(maxTicketAmount, maxLicenseAmount)` — claims mature exit tranches
- `slashTicketBalance(op, amount, reason)` — `onlySlashingManager`; burns tickets, redirects
  underlying
- `slashLicenseBond(op, amount, reason)` — `onlySlashingManager`; decrements bond
- `distributeRewards(token, operators, amounts)` — `onlyAuthorizedDistributor`; pull-payment credits

**State to model (simplified per-operator):**

- Per-operator: ticketBalance, licenseBond, exit tranches (ticket/license amounts +
  unlockTimestamps)
- Global: ticketToken, licenseToken, slashingManager, exitDelay, ticketPrice, minTicketBalance,
  licenseRequiredBond

**Invariants to prove (per-transition, NOT global sums):**

1. `addTicketBalance(op, amount)`: operator's ticket balance increases by amount deposited
2. `removeTicketBalance(op, amount)`: reverts if insufficient balance; otherwise decrements
   correctly
3. `bondLicense(op, amount)`: license bond increases by amount
4. `unbondLicense(op, amount)`: reverts if insufficient bond; queues exit with
   `unlockAt = now + exitDelay`
5. `registerOperator`: only succeeds when not banned, not already registered, licenseBond ≥
   licenseRequiredBond
6. `deregisterOperator`: only succeeds when registered and not in exit, not under open Lane B slash
7. `claimExits`: only claims tranches where `unlockTimestamp ≤ block.timestamp`
8. `slashTicketBalance`: only callable by `slashingManager`; amount ≤ operator's balance
9. `slashLicenseBond`: only callable by `slashingManager`; amount ≤ operator's bond

> **Note on global conservation**: The invariant
> `sum(all ticketBalances) + sum(slashed) = totalDeposited` requires whole-mapping iteration which
> Verity doesn't support. We verify per-transition conservation instead and mark global conservation
> as an assumed property verified by tests.

### 4.4 E3RefundManager.sol — Refund Distribution

**Actual contract behavior** (verified against
`packages/interfold-contracts/contracts/E3RefundManager.sol`):

- `calculateRefund(e3Id, originalPayment, honestNodes, paymentToken)` — `onlyInterfold`; computes
  distribution
- `claimRequesterRefund(e3Id)` — requester pull payment (replay-protected)
- `claimHonestNodeReward(e3Id)` — honest node pull payment (replay-protected)
- `escrowSlashedFunds(e3Id, amount)` — `onlyInterfold`; accumulates pending slashed funds
- `distributeSlashedFundsOnSuccess(e3Id, honestNodes, paymentToken)` — `onlyInterfold`; success-path
  distribution
- `withdrawOrphanedSlashedFunds(e3Id)` — `onlyOwner`; drains funds from E3s that never reached
  terminal state

**State to model:**

- Work allocation BPS: committeeFormation, dkg, decryption, protocol, successSlashedNode
- Per-E3: `_distributions[e3Id]` (requesterAmount, honestNodeAmount, protocolAmount, calculated
  flag)
- Per-E3 per-claimant: `_claimed[e3Id][claimant]` — replay protection
- Per-E3: `_pendingSlashedFunds[e3Id]` — escrowed slashed funds

**Invariants to prove:**

1. Work allocation BPS sum ≤ 10000
2. Refund calculation:
   `requesterAmount + honestNodeAmount + protocolAmount ≤ originalPayment + totalSlashed`
3. Each claimant can only claim once per E3 (`_claimed` replay protection)
4. `claimRequesterRefund` only succeeds for the E3 requester (`NotRequester` error otherwise)
5. `claimHonestNodeReward` only succeeds for honest nodes (`NotHonestNode` error otherwise)
6. `calculateRefund` can only be called once per E3 (idempotent: `_distributions[e3Id].calculated`
   guard)
7. `escrowSlashedFunds` / `distributeSlashedFundsOnSuccess` only callable by Interfold
   (`onlyInterfold` modifier)

### 4.5 SlashingManager.sol — Fault Attribution

**Actual contract behavior** (verified against
`packages/interfold-contracts/contracts/slashing/SlashingManager.sol`):

- `proposeSlash(e3Id, operator, proof)` — Lane A (permissionless, attestation-based, atomic
  execution)
- `proposeSlashByDkgParty(e3Id, partyId, proof)` — Lane A via DKG party attribution
- `proposeSlashEvidence(e3Id, operator, reason, evidence)` — Lane B (SLASHER_ROLE, appeal window)
- `executeSlash(proposalId)` — executes pending Lane B slash after appeal window
- `fileAppeal(proposalId, evidence)` — operator appeal within appeal window
- `resolveAppeal(proposalId, upheld, resolution)` — GOVERNANCE_ROLE appeal resolution
- `proposeBan(node, reason)` / `confirmBan(node, reason)` — two-step governance ban

**State to model:**

- `slashPolicies : bytes32 → SlashPolicy` — per-reason policy config
- `_proposals : uint256 → SlashProposal` — proposal lifecycle
- `banned : address → Bool` — node ban status
- `_consumedEvidence : bytes32 → Bool` — replay protection

**Invariants to prove:**

1. Policy validation: `ticketPenalty > 0 || licensePenalty > 0`
2. Lane B proposals require `appealWindow > 0`; Lane A requires `appealWindow == 0`
3. Proposal lifecycle: can only execute once (`executed` flag prevents double execution)
4. Appeal window enforcement: `executeSlash` reverts if `block.timestamp < executableAt`
5. `fileAppeal` only callable by the slashed operator within appeal window
6. `resolveAppeal` only callable by GOVERNANCE_ROLE
7. Evidence replay protection: `_consumedEvidence[key]` prevents duplicate evidence

## 5. Directory Structure

```
packages/interfold-contracts/
├── contracts/             # Original Solidity (unchanged)
├── verity/                # New Verity verification directory
│   ├── README.md
│   ├── lakefile.lean
│   ├── InterfoldToken/
│   │   ├── InterfoldToken.lean      # EDSL implementation
│   │   ├── Spec.lean                # Formal specifications
│   │   ├── Invariants.lean          # Contract invariants
│   │   └── Proofs/
│   │       └── Basic.lean           # Theorems: impl meets spec
│   ├── InterfoldTicketToken/
│   │   ├── InterfoldTicketToken.lean
│   │   ├── Spec.lean
│   │   ├── Invariants.lean
│   │   └── Proofs/
│   │       └── Basic.lean
│   ├── BondingRegistry/
│   │   ├── BondingRegistry.lean
│   │   ├── Spec.lean
│   │   ├── Invariants.lean
│   │   └── Proofs/
│   │       └── Basic.lean
│   ├── E3RefundManager/
│   │   ├── E3RefundManager.lean
│   │   ├── Spec.lean
│   │   ├── Invariants.lean
│   │   └── Proofs/
│   │       └── Basic.lean
│   ├── SlashingManager/
│   │   ├── SlashingManager.lean
│   │   ├── Spec.lean
│   │   ├── Invariants.lean
│   │   └── Proofs/
│   │       └── Basic.lean
│   └── TrustBoundaries/
│       ├── Oracles.lean            # Oracle declarations for external calls
│       └── Assumptions.lean        # Documented trust assumptions
```

## 6. Implementation Phases

### Phase 0: Setup (Day 1)

**QA Gate**: `lake build` succeeds in cloned Verity repository.

- Clone Verity: `git clone https://github.com/lfglabs-dev/verity.git`
- Build: `cd verity && lake build` (confirms Lean toolchain works)
- Create `packages/interfold-contracts/verity/` directory with `lakefile.lean`
- Run existing Verity examples: `lake build Contracts.SimpleStorage.Proofs.Basic` (verifies
  toolchain)

### Phase 1a: InterfoldToken (Days 2–4)

**TDD Gate (red)**: Run existing Hardhat tests to establish baseline:

```bash
cd packages/interfold-contracts && pnpm test test/Token/InterfoldToken.spec.ts
```

Expected: all existing tests pass (establishes Solidity baseline).

**Implementation steps**:

1. Translate storage layout (slots for totalMinted, transfersRestricted, transferWhitelisted,
   balances, totalSupply)
2. Implement `mintAllocation` in Verity EDSL with `requireSomeUint(safeAdd ...)` for overflow
   protection
3. Implement `_update` transfer hook with whitelist enforcement logic
4. Implement `disableTransferRestrictions` one-way switch
5. Write `_spec` predicates and `_meets_spec` theorems
6. Run `lake build Contracts.InterfoldToken.Proofs.Basic`

**QA Gate (green)**:

```bash
cd packages/interfold-contracts
lake build Contracts.InterfoldToken.Proofs.Basic    # All proofs must pass
lake exe verity-compiler --contract InterfoldToken   # Compiles to Yul without errors
# Verify compiled bytecode against Solidity tests:
pnpm test test/Token/InterfoldToken.spec.ts          # Existing tests still pass
```

### Phase 1b: InterfoldTicketToken (Days 4–6)

**TDD Gate (red)**: `pnpm test test/Token/InterfoldTicketToken.spec.ts` (baseline pass).

**Implementation steps**:

1. Translate storage (underlying, payableBalance, registry, registryLocked)
2. Implement `depositFor` / `depositFrom` with peg maintenance
3. Implement `withdrawTo` with peg maintenance
4. Implement `burnTickets` / `payout` with `onlyRegistry` guard
5. Implement `_update` transfer blocking
6. Implement registry timelock flow (`setRegistry` → `lockRegistry` → `requestRegistryChange` →
   `activateRegistryChange`)
7. Prove: peg maintenance, access control, transfer blocking

**QA Gate (green)**:

```bash
lake build Contracts.InterfoldTicketToken.Proofs.Basic
pnpm test test/Token/InterfoldTicketToken.spec.ts
```

### Phase 2a: BondingRegistry (Days 6–10)

**TDD Gate (red)**: `pnpm test test/Registry/BondingRegistry.spec.ts` (baseline pass).

**Implementation steps**:

1. Translate per-operator storage: ticketBalance, licenseBond, exit tranches
2. Implement `addTicketBalance` / `removeTicketBalance` with SafeERC20 trust boundary
3. Implement `bondLicense` / `unbondLicense` with exit delay enforcement
4. Implement `registerOperator` / `deregisterOperator` lifecycle
5. Implement `claimExits` with maturity check
6. Implement `slashTicketBalance` / `slashLicenseBond` with access control and amount bounds
7. Prove per-transition invariants (not global sums — see §4.3 note)

**QA Gate (green)**:

```bash
lake build Contracts.BondingRegistry.Proofs.Basic
pnpm test test/Registry/BondingRegistry.spec.ts
```

### Phase 2b: E3RefundManager (Days 10–13)

**TDD Gate (red)**: Run relevant E3 lifecycle tests as baseline.

**Implementation steps**:

1. Translate storage: workAllocation, distributions, claimed, pendingSlashedFunds
2. Implement `calculateRefund` with BPS math and idempotency guard
3. Implement `claimRequesterRefund` / `claimHonestNodeReward` with replay protection
4. Implement `escrowSlashedFunds` with `onlyInterfold` guard
5. Prove: BPS sum bound, claim replay protection, access control

**QA Gate (green)**:

```bash
lake build Contracts.E3RefundManager.Proofs.Basic
```

### Phase 2c: SlashingManager (Days 13–16)

**TDD Gate (red)**: `pnpm test test/Slashing/SlashingManager.spec.ts` (baseline pass).

**Implementation steps**:

1. Translate storage: policies, proposals, banned, consumedEvidence
2. Implement `setSlashPolicy` with validation (penalty > 0, appeal window rules)
3. Implement `proposeSlashEvidence` (Lane B) with role check
4. Implement `executeSlash` with appeal window enforcement and single-execution guard
5. Implement `fileAppeal` / `resolveAppeal` lifecycle
6. Implement `proposeBan` / `confirmBan` two-step flow
7. Prove: policy validation, proposal lifecycle, evidence replay protection

**QA Gate (green)**:

```bash
lake build Contracts.SlashingManager.Proofs.Basic
pnpm test test/Slashing/SlashingManager.spec.ts
```

### Phase 3: Trust Report & Documentation (Days 16–18)

**QA Gate**:

```bash
# Generate trust report for all contracts
lake exe verity-compiler --trust-report artifacts/trust-report.json
# Verify no unexpected assumptions
python3 scripts/check_trust_report.py artifacts/trust-report.json
```

Generate:

- Per-contract trust report documenting all assumptions
- Cross-reference against existing Solidity audit findings
- Document all oracle boundaries (external calls, keccak256, ECDSA)

## 7. Risk Assessment & Limitations

### Trust Boundaries (Not Verified)

1. **Cross-contract calls**: BondingRegistry → CiphernodeRegistry, SlashingManager → BondingRegistry
   interactions are oracle assumptions
2. **External token behavior**: SafeERC20 transfer semantics (OpenZeppelin) are trusted
3. **Cryptographic primitives**: keccak256, ECDSA recovery are axiomatized
4. **EVM execution model**: Compiled bytecode correctness depends on solc and EVM spec alignment
5. **ZK proof verification**: All verifier contracts are outside proof envelope

### Verity Limitations Affecting This Work

1. **No whole-mapping reads**: Cannot directly prove global invariants like
   `sum(all balances) == total`. Workaround: per-transition invariants + ghost state
2. **Limited loop support**: Only zero-bound and literal-bound empty-body loops are proved;
   loop-heavy functions (iteration over honest nodes, exit tranches, voters) must have their loop
   bodies simplified or assumed
3. **No inheritance**: Requires explicit composition — increases translation effort but doesn't
   reduce proof power
4. **External calls on trust boundary**: Cross-contract state changes can't be proved within a
   single contract's proof

## 8. Success Criteria

1. **Phase 1**: InterfoldToken + InterfoldTicketToken — all target functions have proven specs,
   `lake build` passes
2. **Phase 2**: BondingRegistry + E3RefundManager + SlashingManager — per-transition invariants
   proved, access control verified
3. **All Verity-compiled contracts** pass existing Hardhat test suite (cross-validation)
4. **Trust report** clearly documents all assumptions and boundaries
5. **No regression** in existing Solidity test coverage
