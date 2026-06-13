/-
  E3RefundManager — Machine-Checked Proofs

  Proves claim replay protection and access control.
-/
import Verity.Core
import Verity.Specs.Common
import E3RefundManager.E3RefundManager
import E3RefundManager.Spec

open Verity

set_option maxHeartbeats 400000

-- Idempotency: calculateRefund can only be called once per E3
theorem calculateRefund_reverts_already_calculated
    (s : ContractState) (e3Id : Uint256) (payment : Uint256)
    (h_interfold : s.sender = s.storageAddr interfoldSlot.slot)
    (h_already : s.storageMap distributionsCalculatedSlot.slot e3Id = true) :
    ((calculateRefund e3Id payment).run s).fst.isRevert := by
  unfold calculateRefund onlyInterfold
  simp [msgSender, getStorageAddr, getMapping,
        interfoldSlot, distributionsCalculatedSlot,
        require, bind, h_interfold, h_already]

-- Claim replay protection
theorem claimRequesterRefund_reverts_already_claimed
    (s : ContractState) (e3Id : Uint256)
    (h_calculated : s.storageMap distributionsCalculatedSlot.slot e3Id = true)
    (h_already_claimed : s.storageMap2 claimedSlot.slot e3Id s.sender = true) :
    ((claimRequesterRefund e3Id).run s).fst.isRevert := by
  unfold claimRequesterRefund
  simp [msgSender, getMapping, getMapping2,
        distributionsCalculatedSlot, claimedSlot, requesterAmountSlot,
        require, bind, h_calculated, h_already_claimed]

-- Claim requires refund to be calculated
theorem claimRequesterRefund_reverts_not_calculated
    (s : ContractState) (e3Id : Uint256) :
    ((claimRequesterRefund e3Id).run s).fst.isRevert := by
  unfold claimRequesterRefund
  simp [msgSender, getMapping, distributionsCalculatedSlot, require, bind]

-- Access control: only Interfold can call calculateRefund
theorem calculateRefund_reverts_non_interfold
    (s : ContractState) (e3Id : Uint256) (payment : Uint256)
    (h_not_interfold : s.sender ≠ s.storageAddr interfoldSlot.slot) :
    ((calculateRefund e3Id payment).run s).fst.isRevert := by
  unfold calculateRefund onlyInterfold
  simp [msgSender, getStorageAddr, interfoldSlot, require, bind, h_not_interfold]

-- Access control: only Interfold can call escrowSlashedFunds
theorem escrowSlashedFunds_reverts_non_interfold
    (s : ContractState) (e3Id : Uint256) (amount : Uint256)
    (h_not_interfold : s.sender ≠ s.storageAddr interfoldSlot.slot) :
    ((escrowSlashedFunds e3Id amount).run s).fst.isRevert := by
  unfold escrowSlashedFunds onlyInterfold
  simp [msgSender, getStorageAddr, interfoldSlot, require, bind, h_not_interfold]

-- setWorkAllocation only callable by owner
theorem setWorkAllocation_reverts_non_owner
    (s : ContractState) (a b c d e : Uint256)
    (h_not_owner : s.sender ≠ s.storageAddr ownerSlot.slot) :
    ((setWorkAllocation a b c d e).run s).fst.isRevert := by
  unfold setWorkAllocation onlyOwner
  simp [msgSender, getStorageAddr, ownerSlot, require, bind, h_not_owner]
