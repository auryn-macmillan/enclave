/-
  BondingRegistry — Formal Specifications

  Each spec is a Prop-valued predicate over pre/post ContractState.
  Specs describe WHAT the function does, not HOW.
-/
import Verity.Specs.Common
import Verity.Macro
import Contracts.BondingRegistry.BondingRegistry

namespace Contracts.BondingRegistry.Spec

open Verity
open Verity.EVM.Uint256
open Contracts.BondingRegistry

/-! ## BR-P1: Slashing access control -/

/-- slashTicketBalance reverts when caller is not the slashing manager. -/
def slashTicketBalance_revert_not_manager
    (operator : Address) (amount : Uint256) (s : ContractState) : Prop :=
  s.sender ≠ s.storage slashingManager.slot →
  ((slashTicketBalance operator amount).run s).fst.isRevert

/-- slashLicenseBond reverts when caller is not the slashing manager. -/
def slashLicenseBond_revert_not_manager
    (operator : Address) (amount : Uint256) (s : ContractState) : Prop :=
  s.sender ≠ s.storage slashingManager.slot →
  ((slashLicenseBond operator amount).run s).fst.isRevert

/-! ## BR-P2: registerOperator reverts when already registered -/

def registerOperator_revert_already_registered
    (s : ContractState) : Prop :=
  s.storageMap registered.slot s.sender = 1 ∧
  s.storageMap exitRequested.slot s.sender = 0 ∧
  s.storageMap licenseBond.slot s.sender ≥ s.storage licenseRequiredBond.slot →
  ((registerOperator).run s).fst.isRevert

/-! ## BR-P3: registerOperator reverts when licenseBond < licenseRequiredBond -/

def registerOperator_revert_insufficient_bond
    (s : ContractState) : Prop :=
  s.storageMap registered.slot s.sender = 0 ∧
  s.storageMap licenseBond.slot s.sender < s.storage licenseRequiredBond.slot →
  ((registerOperator).run s).fst.isRevert

/-! ## BR-P4: registerOperator clears previous exit request -/

/-- On success (modifier passes, checks pass), registerOperator clears the exit request. -/
def registerOperator_clears_exit_spec (s s' : ContractState) : Prop :=
  s'.storageMap exitRequested.slot s.sender = 0 ∧
  s'.storageMap exitUnlocksAt.slot s.sender = 0 ∧
  s'.storageMap registered.slot s.sender = 1

/-! ## BR-P5: deregisterOperator reverts when not registered -/

def deregisterOperator_revert_not_registered
    (s : ContractState) : Prop :=
  s.storageMap registered.slot s.sender = 0 →
  ((deregisterOperator).run s).fst.isRevert

/-! ## BR-P6: bondLicense increments licenseBond -/

/-- On success, bondLicense increments licenseBond by amount. -/
def bondLicense_spec (amount : Uint256) (s s' : ContractState) : Prop :=
  s'.storageMap licenseBond.slot s.sender =
    add (s.storageMap licenseBond.slot s.sender) amount ∧
  storageMapUnchangedExceptKeyAtSlot licenseBond.slot s.sender s s' ∧
  sameAddrMapContext s s'

/-! ## BR-P7: unbondLicense reverts when licenseBond < amount -/

def unbondLicense_revert_insufficient_bond
    (amount : Uint256) (s : ContractState) : Prop :=
  (s.storageMap exitRequested.slot s.sender = 0 ∧
   s.storageMap licenseBond.slot s.sender < amount) →
  ((unbondLicense amount).run s).fst.isRevert

/-! ## BR-P8: unbondLicense decrements licenseBond -/

/-- On success, unbondLicense decrements licenseBond by amount. -/
def unbondLicense_spec (amount : Uint256) (s s' : ContractState) : Prop :=
  s'.storageMap licenseBond.slot s.sender =
    add (s.storageMap licenseBond.slot s.sender) (neg amount) ∧
  storageMapUnchangedExceptKeyAtSlot licenseBond.slot s.sender s s' ∧
  sameAddrMapContext s s'

/-! ## BR-P9: deregisterOperator sets exitUnlocksAt = now + exitDelay -/

/-- On success, deregisterOperator sets exitUnlocksAt to now + exitDelay. -/
def deregisterOperator_exit_delay_spec (s s' : ContractState) : Prop :=
  s'.storageMap exitUnlocksAt.slot s.sender =
    add s.timestamp (s.storage exitDelay.slot) ∧
  s'.storageMap exitRequested.slot s.sender = 1 ∧
  s'.storageMap registered.slot s.sender = 0

end Contracts.BondingRegistry.Spec
