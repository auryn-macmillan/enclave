# Formal Verification Findings — Interfold Smart Contracts

Issues surfaced during the translation of Interfold's Solidity contracts into
Verity's formal verification EDSL.

---

## 1. InterfoldToken: `transfersRestricted` Semantic Direction (Low — naming clarity)

The constructor sets `transfersRestricted = true` and
`disableTransferRestrictions()` sets it to `false`.  
The one-way switch goes **true→false** — restrictions are _disabled_. This is
correct behavior, but the function name `disableTransferRestrictions` sounds
like it should _enable_ restrictions. The NatSpec is clear; the concern is only
for developers reading the function name without the docstring.

**Status**: Behavior is correct. Naming is mildly counterintuitive.

---

## 2. InterfoldToken: "Either Endpoint" Whitelist Check (Low — design clarification)

The `_update` hook enforces
`transferWhitelisted[from] || transferWhitelisted[to]` — **either** party being
whitelisted allows the transfer. A non-whitelisted address can receive from a
whitelisted one, or send to a whitelisted one.

This is the intended bootstrap design (key contracts move tokens while retail
holders are restricted), but it is a weaker restriction than "both must be
whitelisted." Worth being explicit about in user-facing documentation.

**Status**: Design decision. Documented in NatSpec. No code change needed.

---

## 3. BondingRegistry: Global Balance Conservation is Not Locally Provable (Medium — architectural)

**The invariant**:
`sum(all operator ticket balances) + slashedTicketBalance + sum(exit queue tickets) = totalDeposited`

This property spans three contracts (BondingRegistry, InterfoldTicketToken,
ExitQueueLib) and requires whole-mapping iteration to prove. It cannot be
verified in Verity or any bounded proof system without ghost state. It is the
most important safety property in the protocol and currently relies entirely on
integration testing.

**Recommendation**: Add an explicit on-chain `totalDeposited` accumulator that
is incremented on deposits and decremented on withdrawals/slashing, making this
invariant locally verifiable in a single contract.

**Status**: Missing local invariant. Suggested architectural improvement.

---

## 4. E3RefundManager: BPS Sum Validation Missing in `setWorkAllocation` (Medium — potential fund stranding)

The `setWorkAllocation` function accepts individual BPS values but appears to
lack enforcement that their total equals 10000 (100%). The flow-trace documents
describe the BPS breakdown:

- `committeeFormationBps`
- `dkgBps`
- `decryptionBps`
- `protocolBps`
- `successSlashedNodeBps`

If the sum is < 10000, some payment funds would be unallocated (stranded). If >
10000, it would over-allocate. Neither case reverts.

**Recommendation**: Add `require(sum == 10000)` (or `<= 10000` with a documented
sink for the remainder) to the `setWorkAllocation` function.

**Status**: Missing validation. Likely a bug.

---

## 5. Known Issue Confirmed: Deregister-Before-Slash Race in Lane B (Medium — documented trade-off)

The flow-trace documents that an operator can call `deregisterOperator` and
`claimExits` during a Lane B appeal window, potentially draining funds before
`executeSlash` can take them. The formal model confirms: `deregisterOperator`
and `executeSlash` have no mutual exclusion beyond `hasOpenLaneBProposal` (which
only covers unresolved proposals, not the window between appeal expiry and
execution).

The protocol accepts this as a design trade-off, but it means Lane B slashing
guarantees are probabilistic.

**Recommendation**: Consider blocking `deregisterOperator` while ANY Lane B
proposal exists against the operator where `executableAt > block.timestamp` and
`!executed` — not just unresolved proposals.

**Status**: Accepted design trade-off. Documented in flow-trace. Improvement
suggested.

---

## 6. InterfoldTicketToken: `setRegistry` Unrestricted Before `lockRegistry` (Low — deployment sequencing)

Before `lockRegistry()` is called, `setRegistry` can instantly change the
registry address to any address via `onlyOwner`. If the owner key is compromised
before locking, a malicious registry could drain all underlying via `payout`.
The `lockRegistry` mechanism mitigates this, but there is no deadline forcing
the lock.

**Recommendation**: Add the `lockRegistry` call to the deployment checklist as a
mandatory post-deployment step, or consider adding a block-based auto-lock
deadline.

**Status**: Deployment sequencing concern. Not a code bug.

---

## 7. SlashingManager: Unbounded Proposal Count (Low — state bloat / DoS)

`proposeSlashEvidence` increments `totalProposals` without an upper bound. While
Solidity 0.8.x checked arithmetic prevents `Uint256` overflow, an unbounded
proposal count could lead to state bloat. This is not modeled in the Verity
proofs (which avoid loop reasoning), but is worth noting for gas economics.

**Recommendation**: Consider a per-operator or global proposal cap, or document
that slashers are trusted to not spam.

**Status**: Minor gas/state concern. No immediate fix needed.

---

## Summary

| #   | Contract             | Severity | Finding                                                   |
| --- | -------------------- | -------- | --------------------------------------------------------- |
| 1   | InterfoldToken       | Low      | Naming: `disableTransferRestrictions` is counterintuitive |
| 2   | InterfoldToken       | Low      | Whitelist is "either endpoint", not "both"                |
| 3   | BondingRegistry      | Medium   | Global balance conservation not locally provable          |
| 4   | E3RefundManager      | Medium   | BPS sum validation missing in `setWorkAllocation`         |
| 5   | SlashingManager      | Medium   | Deregister-before-slash race in Lane B                    |
| 6   | InterfoldTicketToken | Low      | `setRegistry` unrestricted before `lockRegistry`          |
| 7   | SlashingManager      | Low      | Unbounded proposal count                                  |
