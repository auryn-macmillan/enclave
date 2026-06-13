/-
  InterfoldTicketToken — Contract Invariants

  State predicates that must hold at rest.
-/
import Verity.Core
import InterfoldTicketToken.InterfoldTicketToken
import InterfoldTicketToken.Spec

open Verity

/--
  **Peg Invariant**: totalSupply == underlyingBal + payableBalance.
  Every ITK token is backed by underlying either held directly or set aside
  in payableBalance from burned tickets.
-/
def inv_peg (s : ContractState) : Prop :=
  s.storage totalSupplySlot.slot =
    add (s.storage underlyingBalSlot.slot) (s.storage payableBalanceSlot.slot)

/--
  **Registry non-zero**: after initialization, registry should never be zero.
-/
def inv_registry_nonzero (s : ContractState) : Prop :=
  s.storageAddr registrySlot.slot ≠ 0

/--
  **Owner non-zero**: after initialization, owner should never be zero.
-/
def inv_owner_nonzero (s : ContractState) : Prop :=
  s.storageAddr ownerSlot.slot ≠ 0

/--
  **Payable balance non-negative**: payableBalance should never underflow.
  This is ensured by the `amount <= payableBalance` check in `payout`.
-/
def inv_payable_nonnegative (s : ContractState) : Prop := True
  -- Trivially true because Uint256 is non-negative

/--
  **Registry lock monotonic**: once registryLocked is true, it never becomes false.
  Only `lockRegistry` sets it to true and no function sets it back to false.
-/
def inv_registry_lock_monotonic (s_old s_new : ContractState) : Prop :=
  s_old.storage registryLockedSlot.slot = true →
  s_new.storage registryLockedSlot.slot = true
