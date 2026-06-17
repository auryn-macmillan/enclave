/-
  E3RefundManager — Formal Specifications

  Each spec is a Prop-valued predicate over pre/post ContractState.
  Specs describe WHAT the function does, not HOW.

  Proof objectives covered:
  - E3RM-P1: calculateRefund reverts when already calculated (idempotency)
  - E3RM-P2: claimRequesterRefund reverts when already claimed (replay protection)
  - E3RM-P3: escrowSlashedFunds reverts when caller ≠ Interfold
  - E3RM-P4: calculateRefund reverts when caller ≠ Interfold
  - E3RM-P5: On success, claimRequesterRefund sets claimed[e3Id][sender] = true
-/
import Verity.Specs.Common
import Verity.Macro
import Contracts.E3RefundManager.E3RefundManager

namespace Contracts.E3RefundManager.Spec

open Verity
open Verity.EVM.Uint256
open Contracts.E3RefundManager

/-! ## E3RM-P1 — calculateRefund reverts when already calculated -/

def calculateRefund_revert_calculated (e3Id : Uint256) (originalPayment : Uint256) (s : ContractState) : Prop :=
  (s.storage interfold.slot = s.sender ∧ s.storageMap calculated.slot e3Id = 1) →
  ((calculateRefund e3Id originalPayment).run s).fst.isRevert

/-! ## E3RM-P2 — claimRequesterRefund reverts when already claimed -/

def claimRequesterRefund_revert_claimed (e3Id : Uint256) (s : ContractState) : Prop :=
  (s.storageMap calculated.slot e3Id = 1 ∧ s.storageMap2 claimed.slot e3Id s.sender = 1) →
  ((claimRequesterRefund e3Id).run s).fst.isRevert

/-! ## E3RM-P3 — escrowSlashedFunds reverts without onlyInterfold -/

def escrowSlashedFunds_revert_no_interfold (e3Id : Uint256) (amount : Uint256) (s : ContractState) : Prop :=
  s.storage interfold.slot ≠ s.sender →
  ((escrowSlashedFunds e3Id amount).run s).fst.isRevert

/-! ## E3RM-P4 — calculateRefund reverts without onlyInterfold -/

def calculateRefund_revert_no_interfold (e3Id : Uint256) (originalPayment : Uint256) (s : ContractState) : Prop :=
  s.storage interfold.slot ≠ s.sender →
  ((calculateRefund e3Id originalPayment).run s).fst.isRevert

/-! ## E3RM-P5 — claimRequesterRefund sets claimed[e3Id][sender] = true -/

def claimRequesterRefund_sets_claimed (e3Id : Uint256) (s s' : ContractState) : Prop :=
  (s.storageMap calculated.slot e3Id = 1 ∧
   s.storageMap2 claimed.slot e3Id s.sender = 0 ∧
   s.storageMap requesterAmount.slot e3Id > 0) →
  s'.storageMap2 claimed.slot e3Id s.sender = 1 ∧
  sameAddrMapContext s s'

/-! ## claimHonestNodeReward: sets claimed on success -/

def claimHonestNodeReward_sets_claimed (e3Id : Uint256) (s s' : ContractState) : Prop :=
  (s.storageMap calculated.slot e3Id = 1 ∧
   s.storageMap2 claimed.slot e3Id s.sender = 0 ∧
   s.storageMap perNodeAmount.slot e3Id > 0) →
  s'.storageMap2 claimed.slot e3Id s.sender = 1 ∧
  sameAddrMapContext s s'

/-! ## escrowSlashedFunds increments pending funds on success -/

def escrowSlashedFunds_increments_pending (e3Id : Uint256) (amount : Uint256) (s s' : ContractState) : Prop :=
  (s.storage interfold.slot = s.sender ∧ amount > 0) →
  s'.storageMap pendingSlashedFunds.slot e3Id =
    add (s.storageMap pendingSlashedFunds.slot e3Id) amount ∧
  storageMapUnchangedExceptKeyAtSlot pendingSlashedFunds.slot e3Id s s' ∧
  sameAddrMapContext s s'

end Contracts.E3RefundManager.Spec
