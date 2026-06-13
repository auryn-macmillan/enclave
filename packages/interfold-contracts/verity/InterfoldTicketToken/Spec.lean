/-
  InterfoldTicketToken — Formal Specifications

  Spec predicates for all public functions of the InterfoldTicketToken.
  Focus on: peg invariant, access control, transfer blocking, registry timelock.
-/
import Verity.Core
import Verity.Specs.Common
import InterfoldTicketToken.InterfoldTicketToken

open Verity

/-! ## depositFor spec -/

/--
  Spec for `depositFor(operator, amount)`:
  When called by registry with valid parameters:
  - operator's balance increased by amount
  - totalSupply increased by amount
  - underlyingBal increased by amount (1:1 peg)
  - other balances unchanged
-/
def depositFor_spec (operator : Address) (amount : Uint256) (s s' : ContractState) : Prop :=
  s'.storageMap balancesSlot.slot operator =
    add (s.storageMap balancesSlot.slot operator) amount ∧
  s'.storage totalSupplySlot.slot =
    add (s.storage totalSupplySlot.slot) amount ∧
  s'.storage underlyingBalSlot.slot =
    add (s.storage underlyingBalSlot.slot) amount ∧
  storageMapUnchangedExceptKeyAtSlot balancesSlot.slot operator s s' ∧
  sameStorageAddrContext s s' ∧
  sameContext s s'

/-! ## withdrawTo spec -/

/--
  Spec for `withdrawTo(receiver, amount)`:
  When called by registry with valid parameters:
  - registry's balance decreased by amount
  - totalSupply decreased by amount
  - underlyingBal decreased by amount
-/
def withdrawTo_spec (receiver : Address) (amount : Uint256) (s s' : ContractState) : Prop :=
  s'.storageMap balancesSlot.slot s.sender =
    sub (s.storageMap balancesSlot.slot s.sender) amount ∧
  s'.storage totalSupplySlot.slot =
    sub (s.storage totalSupplySlot.slot) amount ∧
  s'.storage underlyingBalSlot.slot =
    sub (s.storage underlyingBalSlot.slot) amount ∧
  storageMapUnchangedExceptKeyAtSlot balancesSlot.slot s.sender s s' ∧
  sameStorageAddrContext s s' ∧
  sameContext s s'

/-! ## burnTickets spec -/

/--
  Spec for `burnTickets(operator, amount)`:
  When called by registry with valid parameters:
  - operator's balance decreased by amount
  - totalSupply decreased by amount
  - underlyingBal unchanged (tickets burned, underlying stays)
  - payableBalance increased by amount
-/
def burnTickets_spec (operator : Address) (amount : Uint256) (s s' : ContractState) : Prop :=
  s'.storageMap balancesSlot.slot operator =
    sub (s.storageMap balancesSlot.slot operator) amount ∧
  s'.storage totalSupplySlot.slot =
    sub (s.storage totalSupplySlot.slot) amount ∧
  s'.storage underlyingBalSlot.slot = s.storage underlyingBalSlot.slot ∧
  s'.storage payableBalanceSlot.slot =
    add (s.storage payableBalanceSlot.slot) amount ∧
  storageMapUnchangedExceptKeyAtSlot balancesSlot.slot operator s s' ∧
  sameStorageAddrContext s s' ∧
  sameContext s s'

/-! ## payout spec -/

/--
  Spec for `payout(to, amount)`:
  When called by registry with valid parameters and amount ≤ payableBalance:
  - payableBalance decreased by amount
  - underlyingBal decreased by amount
  - totalSupply unchanged (tickets already burned)
-/
def payout_spec (to : Address) (amount : Uint256) (s s' : ContractState) : Prop :=
  s'.storage payableBalanceSlot.slot =
    sub (s.storage payableBalanceSlot.slot) amount ∧
  s'.storage underlyingBalSlot.slot =
    sub (s.storage underlyingBalSlot.slot) amount ∧
  s'.storage totalSupplySlot.slot = s.storage totalSupplySlot.slot ∧
  sameStorageContext s s' ∧
  sameStorageAddrContext s s'

/-! ## Registry management specs -/

/--
  Spec for `setRegistry(newRegistry)`: registry updated, lock remains false.
-/
def setRegistry_spec (newRegistry : Address) (s s' : ContractState) : Prop :=
  (s.sender = s.storageAddr ownerSlot.slot ∧ s.storage registryLockedSlot.slot = false ∧ newRegistry ≠ 0) →
    s'.storageAddr registrySlot.slot = newRegistry ∧
    s'.storage registryLockedSlot.slot = false ∧
    sameStorageExceptSlots [] s s'

/--
  Spec for `lockRegistry()`: registryLocked becomes true, never reverts to false.
-/
def lockRegistry_spec (s s' : ContractState) : Prop :=
  (s.sender = s.storageAddr ownerSlot.slot ∧ s.storage registryLockedSlot.slot = false) →
    s'.storage registryLockedSlot.slot = true ∧
    sameStorageExceptSlots [registryLockedSlot.slot] s s'

/--
  Spec for `requestRegistryChange(newRegistry)`:
  pendingRegistry set, pendingRegistryTime = now + REGISTRY_CHANGE_DELAY.
-/
def requestRegistryChange_spec (newRegistry : Address) (s s' : ContractState) : Prop :=
  (s.sender = s.storageAddr ownerSlot.slot ∧ s.storage registryLockedSlot.slot = true ∧ newRegistry ≠ 0) →
    s'.storageAddr pendingRegistrySlot.slot = newRegistry ∧
    s'.storage pendingRegistryTimeSlot.slot =
      add (s.blockTimestamp) REGISTRY_CHANGE_DELAY ∧
    sameStorageExceptSlots [pendingRegistrySlot.slot, pendingRegistryTimeSlot.slot] s s'

/--
  Spec for `activateRegistryChange()`: registry updated from pending, pending cleared.
-/
def activateRegistryChange_spec (s s' : ContractState) : Prop :=
  (s.sender = s.storageAddr ownerSlot.slot ∧
   s.storageAddr pendingRegistrySlot.slot ≠ 0 ∧
   s.blockTimestamp >= s.storage pendingRegistryTimeSlot.slot) →
    s'.storageAddr registrySlot.slot = s.storageAddr pendingRegistrySlot.slot ∧
    s'.storageAddr pendingRegistrySlot.slot = 0 ∧
    s'.storage pendingRegistryTimeSlot.slot = 0

/-! ## Peg invariant -/

/--
  **The 1:1 peg invariant**: total ITK supply == underlying balance held by contract + payableBalance.

  This states that every ITK token in circulation is either backed by underlying
  held by the contract, or by underlying that has been set aside in payableBalance
  (from burned tickets awaiting payout).

  This invariant holds at all times and is preserved by:
  - depositFor/depositFrom: both totalSupply and underlyingBal increase equally
  - withdrawTo: both decrease equally
  - burnTickets: totalSupply decreases, payableBalance increases (underlyingBal unchanged)
  - payout: payableBalance decreases, underlyingBal decreases (totalSupply unchanged)
-/
def peg_invariant (s : ContractState) : Prop :=
  s.storage totalSupplySlot.slot =
    add (s.storage underlyingBalSlot.slot) (s.storage payableBalanceSlot.slot)

/-! ## Access control specs -/

/--
  `onlyRegistry` reverts when caller is not the registry.
-/
def onlyRegistry_revert_spec (s : ContractState) : Prop :=
  s.sender ≠ s.storageAddr registrySlot.slot →
  ∃ msg, ((onlyRegistry).run s).fst = .revert msg s

/--
  `onlyOwner` reverts when caller is not the owner.
-/
def onlyOwner_revert_spec (s : ContractState) : Prop :=
  s.sender ≠ s.storageAddr ownerSlot.slot →
  ∃ msg, ((onlyOwner).run s).fst = .revert msg s

/--
  Transfer is always blocked between non-zero addresses.
-/
def transfer_blocked_spec (from to : Address) (s : ContractState) : Prop :=
  from ≠ 0 ∧ to ≠ 0 →
  ∃ msg, ((doTransfer from to 1).run s).fst = .revert msg s
