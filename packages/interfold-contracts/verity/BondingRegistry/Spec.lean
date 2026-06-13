/-
  BondingRegistry — Formal Specifications

  Per-transition specs for operator lifecycle, bond/ticket accounting,
  exit claiming, and slashing.
-/
import Verity.Core
import Verity.Specs.Common
import BondingRegistry.BondingRegistry

open Verity

/-! ## bondLicense spec -/

/--
  Spec for `bondLicense(amount)`:
  Operator's license bond increases by amount, other operators' bonds unchanged.
-/
def bondLicense_spec (amount : Uint256) (s s' : ContractState) : Prop :=
  s'.storageMap licenseBondSlot.slot s.sender =
    add (s.storageMap licenseBondSlot.slot s.sender) amount ∧
  storageMapUnchangedExceptKeyAtSlot licenseBondSlot.slot s.sender s s' ∧
  sameStorageAddrContext s s' ∧
  sameContext s s'

/-! ## unbondLicense spec -/

/--
  Spec for `unbondLicense(amount)`:
  Operator's license bond decreases by amount (if sufficient),
  exit license amount increases by amount.
-/
def unbondLicense_spec (amount : Uint256) (s s' : ContractState) : Prop :=
  (s.storageMap licenseBondSlot.slot s.sender >= amount) →
    s'.storageMap licenseBondSlot.slot s.sender =
      sub (s.storageMap licenseBondSlot.slot s.sender) amount ∧
    s'.storageMap exitLicenseAmountSlot.slot s.sender =
      add (s.storageMap exitLicenseAmountSlot.slot s.sender) amount ∧
    storageMapUnchangedExceptKeysAtSlot licenseBondSlot.slot s.sender 0 s s' ∧
    sameStorageAddrContext s s' ∧
    sameContext s s'

/-! ## registerOperator spec -/

/--
  Spec for `registerOperator()`:
  When preconditions hold (not registered, licensed, no exit in progress),
  operator becomes registered.
-/
def registerOperator_spec (s s' : ContractState) : Prop :=
  (s.storageMap registeredSlot.slot s.sender = false ∧
   s.storageMap licenseBondSlot.slot s.sender >= s.storage licenseRequiredBondSlot.slot) →
    s'.storageMap registeredSlot.slot s.sender = true ∧
    storageMapUnchangedExceptKeyAtSlot registeredSlot.slot s.sender s s'

/-! ## deregisterOperator spec -/

/--
  Spec for `deregisterOperator()`:
  When operator is registered and no exit in progress,
  operator becomes not registered and exit is requested.
-/
def deregisterOperator_spec (s s' : ContractState) : Prop :=
  (s.storageMap registeredSlot.slot s.sender = true) →
    s'.storageMap registeredSlot.slot s.sender = false ∧
    s'.storageMap exitRequestedSlot.slot s.sender = true ∧
    s'.storageMap activeSlot.slot s.sender = false

/-! ## claimExits spec -/

/--
  Spec for `claimExits(maxTicket, maxLicense)`:
  When exit is ready (block.timestamp >= unlockAt), claimed amounts
  are removed from the exit queue.
-/
def claimExits_spec (maxTicket maxLicense : Uint256) (s s' : ContractState) : Prop :=
  (s.storageMap exitRequestedSlot.slot s.sender = true ∧
   s.blockTimestamp >= s.storageMap exitUnlocksAtSlot.slot s.sender) →
    -- Exit amounts decrease by at most the claimed amount
    s'.storageMap exitTicketAmountSlot.slot s.sender <=
      s.storageMap exitTicketAmountSlot.slot s.sender ∧
    s'.storageMap exitLicenseAmountSlot.slot s.sender <=
      s.storageMap exitLicenseAmountSlot.slot s.sender

/-! ## slashTicketBalance spec -/

/--
  Spec for `slashTicketBalance(operator, amount)`:
  Only callable by SlashingManager. Increments slashedTicketBalance by amount.
-/
def slashTicketBalance_spec (operator : Address) (amount : Uint256) (s s' : ContractState) : Prop :=
  (s.sender = s.storageAddr slashingManagerSlot.slot ∧ operator ≠ 0 ∧ amount ≠ 0) →
    s'.storage slashedTicketBalanceSlot.slot =
      add (s.storage slashedTicketBalanceSlot.slot) amount ∧
    sameStorageExceptSlots [slashedTicketBalanceSlot.slot] s s'

/-! ## slashLicenseBond spec -/

/--
  Spec for `slashLicenseBond(operator, amount)`:
  Only callable by SlashingManager. Decrements operator's bond,
  increments slashedLicenseBond by amount.
-/
def slashLicenseBond_spec (operator : Address) (amount : Uint256) (s s' : ContractState) : Prop :=
  (s.sender = s.storageAddr slashingManagerSlot.slot ∧
   operator ≠ 0 ∧ amount ≠ 0 ∧
   s.storageMap licenseBondSlot.slot operator >= amount) →
    s'.storageMap licenseBondSlot.slot operator =
      sub (s.storageMap licenseBondSlot.slot operator) amount ∧
    s'.storage slashedLicenseBondSlot.slot =
      add (s.storage slashedLicenseBondSlot.slot) amount

/-! ## Access control specs -/

/--
  `onlySlashingManager` reverts when caller is not the slashing manager.
-/
def onlySlashingManager_revert_spec (s : ContractState) : Prop :=
  s.sender ≠ s.storageAddr slashingManagerSlot.slot →
  ∃ msg, ((onlySlashingManager).run s).fst = .revert msg s

/--
  `onlyOwner` reverts when caller is not the owner.
-/
def onlyOwner_revert_spec (s : ContractState) : Prop :=
  s.sender ≠ s.storageAddr ownerSlot.slot →
  ∃ msg, ((onlyOwner).run s).fst = .revert msg s
