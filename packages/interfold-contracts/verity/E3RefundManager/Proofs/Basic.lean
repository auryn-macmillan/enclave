/-
  E3RefundManager — Machine-Checked Proofs

  Every theorem is complete — NO `sorry` admissions.

  Proof strategy:
  - For revert specs: `verity_unfold` + `simp` with the failing precondition
    to show the `require` emits `ContractResult.revert`.
  - For success specs: `verity_unfold` + `simp` with all positive hypotheses,
    then `rfl` for state assertions.

  Proof objectives covered:
  - E3RM-P1: calculateRefund reverts when already calculated (idempotency)
  - E3RM-P2: claimRequesterRefund reverts when already claimed (replay protection)
  - E3RM-P3: escrowSlashedFunds reverts when caller ≠ Interfold
  - E3RM-P4: calculateRefund reverts when caller ≠ Interfold
  - E3RM-P5: On success, claimRequesterRefund sets claimed[e3Id][sender] = true
  - Bonus: claimHonestNodeReward sets claimed on success
  - Bonus: escrowSlashedFunds correctly increments pendingSlashedFunds
-/
import Contracts.E3RefundManager.Spec
import Verity.Proofs.Stdlib.Automation

namespace Contracts.E3RefundManager.Proofs

open Verity
open Verity.EVM.Uint256
open Contracts.E3RefundManager
open Contracts.E3RefundManager.Spec

set_option maxHeartbeats 400000

/-! ## E3RM-P4: calculateRefund reverts without onlyInterfold -/

theorem calculateRefund_revert_no_interfold
    (s : ContractState) (e3Id : Uint256) (originalPayment : Uint256)
    (h_no_interfold : s.storage interfold.slot ≠ s.sender) :
    ((calculateRefund e3Id originalPayment).run s).fst.isRevert := by
  verity_unfold calculateRefund
  simp only [onlyInterfold, msgSender, getStorage, require, bind,
             interfold, h_no_interfold]
  exact ContractResult.revert_isRevert _

/-! ## E3RM-P1: calculateRefund reverts when already calculated (idempotency) -/

theorem calculateRefund_revert_already_calculated
    (s : ContractState) (e3Id : Uint256) (originalPayment : Uint256)
    (h_interfold : s.storage interfold.slot = s.sender)
    (h_calculated : s.storageMap calculated.slot e3Id = 1) :
    ((calculateRefund e3Id originalPayment).run s).fst.isRevert := by
  verity_unfold calculateRefund
  simp only [onlyInterfold, msgSender, getStorage, getMapping, require, bind,
             interfold, calculated, h_interfold, h_calculated]
  exact ContractResult.revert_isRevert _

/-! ## E3RM-P3: escrowSlashedFunds reverts without onlyInterfold -/

theorem escrowSlashedFunds_revert_no_interfold
    (s : ContractState) (e3Id : Uint256) (amount : Uint256)
    (h_no_interfold : s.storage interfold.slot ≠ s.sender) :
    ((escrowSlashedFunds e3Id amount).run s).fst.isRevert := by
  verity_unfold escrowSlashedFunds
  simp only [onlyInterfold, msgSender, getStorage, require, bind,
             interfold, h_no_interfold]
  exact ContractResult.revert_isRevert _

/-! ## E3RM-P2: claimRequesterRefund reverts when already claimed (replay protection) -/

theorem claimRequesterRefund_revert_already_claimed
    (s : ContractState) (e3Id : Uint256)
    (h_calculated : s.storageMap calculated.slot e3Id = 1)
    (h_claimed : s.storageMap2 claimed.slot e3Id s.sender = 1) :
    ((claimRequesterRefund e3Id).run s).fst.isRevert := by
  verity_unfold claimRequesterRefund
  simp only [getMapping, getMapping2, require, bind, msgSender,
             calculated, claimed, h_calculated, h_claimed]
  exact ContractResult.revert_isRevert _

/-! ## E3RM-P5: claimRequesterRefund sets claimed[e3Id][sender] = true on success -/

theorem claimRequesterRefund_sets_claimed
    (s : ContractState) (e3Id : Uint256)
    (h_calculated : s.storageMap calculated.slot e3Id = 1)
    (h_not_claimed : s.storageMap2 claimed.slot e3Id s.sender = 0)
    (h_amount : s.storageMap requesterAmount.slot e3Id > 0) :
    ((claimRequesterRefund e3Id).run s).snd.storageMap2 claimed.slot e3Id s.sender = 1 := by
  verity_unfold claimRequesterRefund
  simp only [getMapping, getMapping2, setMapping2, setMapping, require, requireSomeUint,
             safeAdd, bind, msgSender, addressToWord, emitEvent,
             calculated, claimed, requesterAmount, claimCount,
             h_calculated, h_not_claimed, h_amount]
  rfl

/-! ## claimHonestNodeReward: sets claimed on success (same replay protection) -/

theorem claimHonestNodeReward_sets_claimed
    (s : ContractState) (e3Id : Uint256)
    (h_calculated : s.storageMap calculated.slot e3Id = 1)
    (h_not_claimed : s.storageMap2 claimed.slot e3Id s.sender = 0)
    (h_amount : s.storageMap perNodeAmount.slot e3Id > 0) :
    ((claimHonestNodeReward e3Id).run s).snd.storageMap2 claimed.slot e3Id s.sender = 1 := by
  verity_unfold claimHonestNodeReward
  simp only [getMapping, getMapping2, setMapping2, setMapping, require, requireSomeUint,
             safeAdd, bind, msgSender, addressToWord, emitEvent,
             calculated, claimed, perNodeAmount, claimCount,
             h_calculated, h_not_claimed, h_amount]
  rfl

/-! ## claimHonestNodeReward reverts when already claimed -/

theorem claimHonestNodeReward_revert_already_claimed
    (s : ContractState) (e3Id : Uint256)
    (h_calculated : s.storageMap calculated.slot e3Id = 1)
    (h_claimed : s.storageMap2 claimed.slot e3Id s.sender = 1) :
    ((claimHonestNodeReward e3Id).run s).fst.isRevert := by
  verity_unfold claimHonestNodeReward
  simp only [getMapping, getMapping2, require, bind, msgSender,
             calculated, claimed, h_calculated, h_claimed]
  exact ContractResult.revert_isRevert _

/-! ## escrowSlashedFunds increments pendingSlashedFunds on success -/

theorem escrowSlashedFunds_increments_pending
    (s : ContractState) (e3Id : Uint256) (amount : Uint256)
    (h_interfold : s.storage interfold.slot = s.sender)
    (h_amount : amount > 0) :
    ((escrowSlashedFunds e3Id amount).run s).snd.storageMap pendingSlashedFunds.slot e3Id =
      add (s.storageMap pendingSlashedFunds.slot e3Id) amount := by
  verity_unfold escrowSlashedFunds
  simp only [onlyInterfold, msgSender, getStorage, getMapping, setMapping, require,
             requireSomeUint, safeAdd, bind, emitEvent,
             interfold, pendingSlashedFunds, h_interfold, h_amount]
  rfl

/-! ## Access control: distributeSlashedFundsOnSuccess reverts without onlyInterfold -/

theorem distributeSlashedFundsOnSuccess_revert_no_interfold
    (s : ContractState) (e3Id : Uint256)
    (h_no_interfold : s.storage interfold.slot ≠ s.sender) :
    ((distributeSlashedFundsOnSuccess e3Id).run s).fst.isRevert := by
  verity_unfold distributeSlashedFundsOnSuccess
  simp only [onlyInterfold, msgSender, getStorage, require, bind,
             interfold, h_no_interfold]
  exact ContractResult.revert_isRevert _

/-! ## Access control: setWorkAllocation reverts without owner -/

theorem setWorkAllocation_revert_no_owner
    (s : ContractState)
    (h_no_owner : s.storage owner.slot ≠ s.sender) :
    ((setWorkAllocation).run s).fst.isRevert := by
  verity_unfold setWorkAllocation
  simp only [onlyOwner, msgSender, getStorage, require, bind,
             owner, h_no_owner]
  exact ContractResult.revert_isRevert _

/-! ## Access control: withdrawOrphanedSlashedFunds reverts without owner -/

theorem withdrawOrphanedSlashedFunds_revert_no_owner
    (s : ContractState) (e3Id : Uint256)
    (h_no_owner : s.storage owner.slot ≠ s.sender) :
    ((withdrawOrphanedSlashedFunds e3Id).run s).fst.isRevert := by
  verity_unfold withdrawOrphanedSlashedFunds
  simp only [onlyOwner, msgSender, getStorage, require, bind,
             owner, h_no_owner]
  exact ContractResult.revert_isRevert _

end Contracts.E3RefundManager.Proofs
