# Formal Verification Findings — Interfold Smart Contracts

Issues surfaced during the translation of Interfold's Solidity contracts into
Verity's formal verification EDSL.

---

## 1. E3RefundManager: BPS Sum Validation Missing in `setWorkAllocation` (Medium — potential fund stranding)

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

## 2. BondingRegistry: Global Balance Conservation is Not Locally Provable (Medium — architectural)

**The invariant**:
`sum(all operator ticket balances) + slashedTicketBalance + sum(exit queue tickets) = totalDeposited`

This property spans three contracts (BondingRegistry, InterfoldTicketToken,
ExitQueueLib) and requires whole-mapping iteration to prove. It cannot be
verified in Verity (which doesn't support whole-mapping reads) without ghost
state. It is the most important safety property in the protocol and currently
relies entirely on integration testing.

**Recommendation**: Add an explicit on-chain `totalDeposited` accumulator that
is incremented on deposits and decremented on withdrawals/slashing, making this
invariant locally verifiable in a single contract.

**Status**: Missing local invariant. Suggested architectural improvement.

---

## 3. Deregister-Before-Slash Race in Lane B (Medium — documented trade-off)

The flow-trace documents that an operator can call `deregisterOperator` and
`claimExits` during a Lane B appeal window, potentially draining funds before
`executeSlash` can take them. The Solidity code checks `hasOpenLaneBProposal`
before allowing deregistration, but this only covers unresolved proposals — not
the window between appeal expiry and execution.

The protocol accepts this as a design trade-off, but it means Lane B slashing
guarantees are probabilistic.

**Recommendation**: Consider blocking `deregisterOperator` while ANY Lane B
proposal exists against the operator where `executableAt > block.timestamp` and
`!executed`.

**Status**: Accepted design trade-off. Documented in flow-trace. Improvement
suggested.

---

## 4. InterfoldTicketToken: `setRegistry` Unrestricted Before `lockRegistry` (Low — deployment sequencing)

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

## 5. SlashingManager: Unbounded Proposal Count (Low — state bloat / DoS)

`proposeSlashEvidence` increments `totalProposals` without an upper bound. While
Solidity 0.8.x checked arithmetic prevents `Uint256` overflow, an unbounded
proposal count could lead to state bloat.

**Recommendation**: Consider a per-operator or global proposal cap, or document
that slashers are trusted to not spam.

**Status**: Minor gas/state concern. No immediate fix needed.

---

## Summary

| #   | Contract             | Severity | Finding                                           |
| --- | -------------------- | -------- | ------------------------------------------------- |
| 1   | E3RefundManager      | Medium   | BPS sum validation missing in `setWorkAllocation` |
| 2   | BondingRegistry      | Medium   | Global balance conservation not locally provable  |
| 3   | SlashingManager      | Medium   | Deregister-before-slash race in Lane B            |
| 4   | InterfoldTicketToken | Low      | `setRegistry` unrestricted before `lockRegistry`  |
| 5   | SlashingManager      | Low      | Unbounded proposal count                          |
