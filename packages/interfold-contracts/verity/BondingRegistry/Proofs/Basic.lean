/-
  BondingRegistry — Machine-Checked Proofs

  Every theorem is complete — NO `sorry` admissions.

  Proof strategy:
  - For success-path specs: `verity_unfold` + `refine` to match the spec triple,
    then `simp` with slot names and hypotheses.
  - For revert specs: unfold the function, `simp` with the failing precondition
    to show the `require` emits `ContractResult.revert`.
  - safeAdd / safeSub always return `some` in the functional model;
    overflow is enforced only at EVM compilation time.
  - requireSomeUint unwraps the option; require enforces explicit guards.
-/
import Contracts.BondingRegistry.Spec
import Verity.Proofs.Stdlib.Automation

namespace Contracts.BondingRegistry.Proofs

open Verity
open Verity.EVM.Uint256
open Contracts.BondingRegistry
open Contracts.BondingRegistry.Spec

set_option maxHeartbeats 400000

/-! ## BR-P1: slashTicketBalance reverts when caller is not slashing manager -/

theorem slashTicketBalance_revert_not_manager
    (s : ContractState) (operator : Address) (amount : Uint256)
    (h_not_manager : s.sender ≠ s.storage slashingManager.slot) :
    ((slashTicketBalance operator amount).run s).fst.isRevert := by
  verity_unfold slashTicketBalance
  simp only [onlySlashingManager, msgSender, getStorage, require, bind,
             slashingManager, h_not_manager]
  exact ContractResult.revert_isRevert _

/-! ## BR-P1: slashLicenseBond reverts when caller is not slashing manager -/

theorem slashLicenseBond_revert_not_manager
    (s : ContractState) (operator : Address) (amount : Uint256)
    (h_not_manager : s.sender ≠ s.storage slashingManager.slot) :
    ((slashLicenseBond operator amount).run s).fst.isRevert := by
  verity_unfold slashLicenseBond
  simp only [onlySlashingManager, msgSender, getStorage, require, bind,
             slashingManager, h_not_manager]
  exact ContractResult.revert_isRevert _

/-! ## BR-P2: registerOperator reverts when already registered -/

theorem registerOperator_revert_already_registered
    (s : ContractState)
    (h_already : s.storageMap registered.slot s.sender = 1)
    (h_no_exit : s.storageMap exitRequested.slot s.sender = 0)
    (h_bond : s.storageMap licenseBond.slot s.sender ≥ s.storage licenseRequiredBond.slot) :
    ((registerOperator).run s).fst.isRevert := by
  verity_unfold registerOperator
  simp only [noExitInProgress, msgSender, getMapping, setMapping, getStorage,
             require, getBlockTimestamp, bind, if_pos, if_neg,
             registered, exitRequested, exitUnlocksAt, licenseBond, licenseRequiredBond,
             h_already, h_no_exit, h_bond]
  exact ContractResult.revert_isRevert _

/-! ## BR-P3: registerOperator reverts when licenseBond < licenseRequiredBond -/

theorem registerOperator_revert_insufficient_bond
    (s : ContractState)
    (h_not_reg : s.storageMap registered.slot s.sender = 0)
    (h_bond_low : s.storageMap licenseBond.slot s.sender < s.storage licenseRequiredBond.slot)
    (h_no_exit : s.storageMap exitRequested.slot s.sender = 0) :
    ((registerOperator).run s).fst.isRevert := by
  verity_unfold registerOperator
  simp only [noExitInProgress, msgSender, getMapping, getStorage,
             require, getBlockTimestamp, bind, if_neg,
             registered, exitRequested, licenseBond, licenseRequiredBond,
             h_not_reg, h_no_exit, h_bond_low]
  exact ContractResult.revert_isRevert _

/-! ## BR-P4: registerOperator clears previous exit request -/

theorem registerOperator_clears_exit
    (s : ContractState)
    (h_exit_req : s.storageMap exitRequested.slot s.sender = 1)
    (h_time : s.timestamp ≥ s.storageMap exitUnlocksAt.slot s.sender)
    (h_not_reg : s.storageMap registered.slot s.sender = 0)
    (h_bond : s.storageMap licenseBond.slot s.sender ≥ s.storage licenseRequiredBond.slot) :
    let s' := ((registerOperator).run s).snd
    registerOperator_clears_exit_spec s s' := by
  intro s'
  unfold registerOperator_clears_exit_spec
  verity_unfold registerOperator
  simp only [noExitInProgress, msgSender, getMapping, setMapping, getStorage,
             require, getBlockTimestamp, requireSomeUint, safeAdd, safeSub,
             bind, if_pos, if_neg, pure,
             registered, exitRequested, exitUnlocksAt, licenseBond, licenseRequiredBond,
             h_exit_req, h_time, h_not_reg, h_bond, emitEvent]
  refine ⟨?_, ?_, ?_⟩
  · rfl
  · rfl
  · rfl

/-! ## BR-P5: deregisterOperator reverts when not registered -/

theorem deregisterOperator_revert_not_registered
    (s : ContractState)
    (h_not_reg : s.storageMap registered.slot s.sender = 0) :
    ((deregisterOperator).run s).fst.isRevert := by
  verity_unfold deregisterOperator
  simp only [noExitInProgress, msgSender, getMapping, getStorage,
             require, getBlockTimestamp, bind, if_neg,
             registered, exitRequested, h_not_reg]
  exact ContractResult.revert_isRevert _

/-! ## BR-P6: bondLicense increments licenseBond -/

theorem bondLicense_meets_spec
    (s : ContractState) (amount : Uint256)
    (h_amount : amount ≠ 0)
    (h_no_exit : s.storageMap exitRequested.slot s.sender = 0) :
    let s' := ((bondLicense amount).run s).snd
    bondLicense_spec amount s s' := by
  intro s'
  unfold bondLicense_spec
  verity_unfold bondLicense
  simp only [noExitInProgress, msgSender, getMapping, setMapping,
             require, getBlockTimestamp, requireSomeUint, safeAdd,
             bind, if_pos, if_neg, pure,
             exitRequested, exitUnlocksAt, licenseBond,
             h_amount, h_no_exit, emitEvent]
  refine ⟨?_, ?_, ?_⟩
  · simp [Contract.run]
  · simp [Contract.run]
  · simp [Contract.run]

/-! ## BR-P7: unbondLicense reverts when licenseBond < amount -/

theorem unbondLicense_revert_insufficient_bond
    (s : ContractState) (amount : Uint256)
    (h_no_exit : s.storageMap exitRequested.slot s.sender = 0)
    (h_bond_low : s.storageMap licenseBond.slot s.sender < amount) :
    ((unbondLicense amount).run s).fst.isRevert := by
  verity_unfold unbondLicense
  simp only [noExitInProgress, msgSender, getMapping, getStorage,
             require, getBlockTimestamp, bind, if_neg,
             exitRequested, licenseBond, h_no_exit, h_bond_low]
  exact ContractResult.revert_isRevert _

/-! ## BR-P8: unbondLicense decrements licenseBond -/

theorem unbondLicense_meets_spec
    (s : ContractState) (amount : Uint256)
    (h_amount : amount ≠ 0)
    (h_no_exit : s.storageMap exitRequested.slot s.sender = 0)
    (h_bond_geq : s.storageMap licenseBond.slot s.sender ≥ amount) :
    let s' := ((unbondLicense amount).run s).snd
    unbondLicense_spec amount s s' := by
  intro s'
  unfold unbondLicense_spec
  verity_unfold unbondLicense
  simp only [noExitInProgress, msgSender, getMapping, setMapping,
             require, getBlockTimestamp, requireSomeUint, safeSub,
             bind, if_pos, if_neg, pure,
             exitRequested, exitUnlocksAt, licenseBond,
             h_amount, h_no_exit, h_bond_geq, emitEvent]
  refine ⟨?_, ?_, ?_⟩
  · simp [Contract.run]
  · simp [Contract.run]
  · simp [Contract.run]

/-! ## BR-P9: deregisterOperator sets exitUnlocksAt = now + exitDelay -/

theorem deregisterOperator_exit_delay
    (s : ContractState)
    (h_reg : s.storageMap registered.slot s.sender = 1)
    (h_no_exit : s.storageMap exitRequested.slot s.sender = 0) :
    let s' := ((deregisterOperator).run s).snd
    deregisterOperator_exit_delay_spec s s' := by
  intro s'
  unfold deregisterOperator_exit_delay_spec
  verity_unfold deregisterOperator
  simp only [noExitInProgress, msgSender, getMapping, setMapping, getStorage,
             require, getBlockTimestamp, requireSomeUint, safeAdd,
             bind, if_pos, if_neg, pure,
             registered, exitRequested, exitUnlocksAt, exitDelay,
             h_reg, h_no_exit, emitEvent]
  refine ⟨?_, ?_, ?_⟩
  · simp [Contract.run]
  · simp [Contract.run]
  · simp [Contract.run]

end Contracts.BondingRegistry.Proofs
