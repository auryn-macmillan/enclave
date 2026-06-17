/-
  SlashingManager — Formal Specifications

  Each spec is a Prop-valued predicate over pre/post ContractState.
  Specs describe WHAT the function does, not HOW.
-/
import Verity.Specs.Common
import Verity.Macro
import Contracts.SlashingManager.SlashingManager

namespace Contracts.SlashingManager.Spec

open Verity
open Verity.EVM.Uint256
open Contracts.SlashingManager

/-! ## SM-P1: setSlashPolicy reverts when no penalty is defined -/

/-- setSlashPolicy revert spec: reverts when ticketPenalty == 0 && licensePenalty == 0 -/
def setSlashPolicy_revert_no_penalty
    (reason ticketPenalty licensePenalty appealWindow enabled requiresProof : Uint256)
    (s : ContractState) : Prop :=
  (s.storageMap2 roleMembers.slot GOVERNANCE_ROLE s.sender = 1 ∧
   ticketPenalty = 0 ∧ licensePenalty = 0) →
  ((setSlashPolicy reason ticketPenalty licensePenalty appealWindow enabled requiresProof).run s).fst.isRevert

/-! ## SM-P2: setSlashPolicy reverts when Lane B has no appeal window -/

/-- setSlashPolicy revert spec: reverts when requiresProof == 0 && appealWindow == 0 (Lane B needs appeal window) -/
def setSlashPolicy_revert_no_appeal_window
    (reason ticketPenalty licensePenalty appealWindow enabled requiresProof : Uint256)
    (s : ContractState) : Prop :=
  (s.storageMap2 roleMembers.slot GOVERNANCE_ROLE s.sender = 1 ∧
   (ticketPenalty > 0 ∨ licensePenalty > 0) ∧
   requiresProof = 0 ∧ appealWindow = 0) →
  ((setSlashPolicy reason ticketPenalty licensePenalty appealWindow enabled requiresProof).run s).fst.isRevert

/-! ## SM-P3: executeSlash reverts when proposal already executed -/

/-- executeSlash revert spec: reverts when proposal already executed -/
def executeSlash_revert_executed (proposalId : Uint256) (s : ContractState) : Prop :=
  s.storageMap proposal_executed.slot proposalId = 1 →
  ((executeSlash proposalId).run s).fst.isRevert

/-! ## SM-P4: executeSlash reverts when block.timestamp < executableAt -/

/-- executeSlash revert spec: reverts when the appeal window is still active -/
def executeSlash_revert_window_active (proposalId : Uint256) (s : ContractState) : Prop :=
  (s.storageMap proposal_executed.slot proposalId = 0 ∧
   s.storageMap proposal_appealed.slot proposalId = 0 ∧
   s.storageMap proposal_executableAt.slot proposalId > s.blockTimestamp) →
  ((executeSlash proposalId).run s).fst.isRevert

/-! ## SM-P5: fileAppeal reverts when msg.sender is not the operator -/

/-- fileAppeal revert spec: reverts when caller is not the proposal operator -/
def fileAppeal_revert_unauthorized (proposalId : Uint256) (s : ContractState) : Prop :=
  s.storageMap2 proposal_operator.slot proposalId s.sender ≠ 1 →
  ((fileAppeal proposalId).run s).fst.isRevert

/-! ## SM-P6: fileAppeal reverts when appeal window has expired -/

/-- fileAppeal revert spec: reverts when block.timestamp >= executableAt -/
def fileAppeal_revert_window_expired (proposalId : Uint256) (s : ContractState) : Prop :=
  (s.storageMap2 proposal_operator.slot proposalId s.sender = 1 ∧
   s.storageMap proposal_executed.slot proposalId = 0 ∧
   s.storageMap proposal_appealed.slot proposalId = 0 ∧
   s.storageMap proposal_executableAt.slot proposalId ≤ s.blockTimestamp) →
  ((fileAppeal proposalId).run s).fst.isRevert

/-! ## SM-P7: resolveAppeal reverts when caller lacks GOVERNANCE_ROLE -/

/-- resolveAppeal revert spec: reverts without GOVERNANCE_ROLE -/
def resolveAppeal_revert_no_role (proposalId : Uint256) (upheld : Uint256) (s : ContractState) : Prop :=
  s.storageMap2 roleMembers.slot GOVERNANCE_ROLE s.sender ≠ 1 →
  ((resolveAppeal proposalId upheld).run s).fst.isRevert

/-! ## SM-P8: confirmBan reverts when already banned -/

/-- confirmBan revert spec: reverts when node is already banned -/
def confirmBan_revert_already_banned (node : Address) (reason : Uint256) (s : ContractState) : Prop :=
  (s.storageMap2 roleMembers.slot GOVERNANCE_ROLE s.sender = 1 ∧
   s.storageMap banned.slot node = 1) →
  ((confirmBan node reason).run s).fst.isRevert

end Contracts.SlashingManager.Spec
