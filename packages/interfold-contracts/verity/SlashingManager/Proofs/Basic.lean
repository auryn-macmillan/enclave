/-
  SlashingManager — Machine-Checked Proofs

  Every theorem is complete — NO `sorry` admissions.

  Proof strategy:
  - For revert specs: `verity_unfold` the function, then `simp` with the failing
    precondition to show the `require` emits `ContractResult.revert`.
  - For access control reverts: unfold the guard function + the target function,
    `simp` with the missing-role hypothesis.
  - For conditional logic (if/else): `simp` with `if_pos` / `if_neg` and the
    relevant hypotheses to reduce the branch.

  Proof objectives (see PROOF_OBJECTIVES.md):
  - SM-P1: setSlashPolicy revert — no penalty
  - SM-P2: setSlashPolicy revert — Lane B needs appeal window
  - SM-P3: executeSlash revert — already executed
  - SM-P4: executeSlash revert — appeal window active
  - SM-P5: fileAppeal revert — unauthorized caller
  - SM-P6: fileAppeal revert — appeal window expired
  - SM-P7: resolveAppeal revert — missing GOVERNANCE_ROLE
  - SM-P8: confirmBan revert — already banned
-/
import Contracts.SlashingManager.Spec
import Verity.Proofs.Stdlib.Automation

namespace Contracts.SlashingManager.Proofs

open Verity
open Verity.EVM.Uint256
open Contracts.SlashingManager
open Contracts.SlashingManager.Spec

set_option maxHeartbeats 400000

/-! ## SM-P1: setSlashPolicy reverts when ticketPenalty == 0 && licensePenalty == 0 -/

theorem setSlashPolicy_revert_no_penalty
    (s : ContractState) (reason ticketPenalty licensePenalty appealWindow enabled requiresProof : Uint256)
    (h_role : s.storageMap2 roleMembers.slot GOVERNANCE_ROLE s.sender = 1)
    (h_no_ticket : ticketPenalty = 0)
    (h_no_license : licensePenalty = 0) :
    ((setSlashPolicy reason ticketPenalty licensePenalty appealWindow enabled requiresProof).run s).fst.isRevert := by
  verity_unfold setSlashPolicy
  simp only [onlyGovernance, msgSender, getMapping2, getMapping, setMapping,
              require, bind, if_neg,
              roleMembers, GOVERNANCE_ROLE, SLASHER_ROLE,
              policy_ticketPenalty, policy_licensePenalty, policy_appealWindow,
              policy_enabled, policy_requiresProof,
              h_role, h_no_ticket, h_no_license]
  exact ContractResult.revert_isRevert _

/-! ## SM-P2: setSlashPolicy reverts when Lane B (no proof) lacks appeal window -/

theorem setSlashPolicy_revert_no_appeal_window
    (s : ContractState) (reason ticketPenalty licensePenalty appealWindow enabled requiresProof : Uint256)
    (h_role : s.storageMap2 roleMembers.slot GOVERNANCE_ROLE s.sender = 1)
    (h_penalty : ticketPenalty > 0 ∨ licensePenalty > 0)
    (h_no_proof : requiresProof = 0)
    (h_no_window : appealWindow = 0) :
    ((setSlashPolicy reason ticketPenalty licensePenalty appealWindow enabled requiresProof).run s).fst.isRevert := by
  verity_unfold setSlashPolicy
  cases h_penalty with
  | inl h_ticket =>
      simp only [onlyGovernance, msgSender, getMapping2, getMapping, setMapping,
                  require, bind, if_pos, if_neg,
                  roleMembers, GOVERNANCE_ROLE, SLASHER_ROLE,
                  policy_ticketPenalty, policy_licensePenalty, policy_appealWindow,
                  policy_enabled, policy_requiresProof,
                  h_role, h_ticket, h_no_proof, h_no_window]
      exact ContractResult.revert_isRevert _
  | inr h_license =>
      simp only [onlyGovernance, msgSender, getMapping2, getMapping, setMapping,
                  require, bind, if_pos, if_neg,
                  roleMembers, GOVERNANCE_ROLE, SLASHER_ROLE,
                  policy_ticketPenalty, policy_licensePenalty, policy_appealWindow,
                  policy_enabled, policy_requiresProof,
                  h_role, h_license, h_no_proof, h_no_window]
      exact ContractResult.revert_isRevert _

/-! ## SM-P3: executeSlash reverts when proposal already executed -/

theorem executeSlash_revert_executed
    (s : ContractState) (proposalId : Uint256)
    (h_executed : s.storageMap proposal_executed.slot proposalId = 1) :
    ((executeSlash proposalId).run s).fst.isRevert := by
  verity_unfold executeSlash
  simp only [getMapping, require, bind,
              proposal_executed, proposal_appealed, proposal_resolved, proposal_upheld,
              proposal_executableAt, proposal_operator,
              h_executed]
  exact ContractResult.revert_isRevert _

/-! ## SM-P4: executeSlash reverts when block.timestamp < executableAt -/

theorem executeSlash_revert_window_active
    (s : ContractState) (proposalId : Uint256)
    (h_not_executed : s.storageMap proposal_executed.slot proposalId = 0)
    (h_not_appealed : s.storageMap proposal_appealed.slot proposalId = 0)
    (h_future : s.storageMap proposal_executableAt.slot proposalId > s.blockTimestamp) :
    ((executeSlash proposalId).run s).fst.isRevert := by
  verity_unfold executeSlash
  simp only [getMapping, require, bind, if_neg,
              proposal_executed, proposal_appealed, proposal_resolved, proposal_upheld,
              proposal_executableAt, proposal_operator,
              h_not_executed, h_not_appealed, h_future]
  exact ContractResult.revert_isRevert _

/-! ## SM-P5: fileAppeal reverts when msg.sender is not the operator -/

theorem fileAppeal_revert_unauthorized
    (s : ContractState) (proposalId : Uint256)
    (h_not_op : s.storageMap2 proposal_operator.slot proposalId s.sender ≠ 1) :
    ((fileAppeal proposalId).run s).fst.isRevert := by
  verity_unfold fileAppeal
  simp only [msgSender, getMapping2, getMapping, require, bind,
              proposal_operator, proposal_executed, proposal_appealed,
              proposal_executableAt,
              h_not_op]
  exact ContractResult.revert_isRevert _

/-! ## SM-P6: fileAppeal reverts when appeal window has expired -/

theorem fileAppeal_revert_window_expired
    (s : ContractState) (proposalId : Uint256)
    (h_is_op : s.storageMap2 proposal_operator.slot proposalId s.sender = 1)
    (h_not_executed : s.storageMap proposal_executed.slot proposalId = 0)
    (h_not_appealed : s.storageMap proposal_appealed.slot proposalId = 0)
    (h_expired : s.storageMap proposal_executableAt.slot proposalId ≤ s.blockTimestamp) :
    ((fileAppeal proposalId).run s).fst.isRevert := by
  verity_unfold fileAppeal
  simp only [msgSender, getMapping2, getMapping, require, bind, if_neg,
              proposal_operator, proposal_executed, proposal_appealed,
              proposal_executableAt,
              h_is_op, h_not_executed, h_not_appealed, h_expired]
  exact ContractResult.revert_isRevert _

/-! ## SM-P7: resolveAppeal reverts when caller lacks GOVERNANCE_ROLE -/

theorem resolveAppeal_revert_no_role
    (s : ContractState) (proposalId : Uint256) (upheld : Uint256)
    (h_no_role : s.storageMap2 roleMembers.slot GOVERNANCE_ROLE s.sender ≠ 1) :
    ((resolveAppeal proposalId upheld).run s).fst.isRevert := by
  verity_unfold resolveAppeal
  simp only [onlyGovernance, msgSender, getMapping2, require, bind,
              roleMembers, GOVERNANCE_ROLE,
              proposal_appealed, proposal_resolved, proposal_upheld,
              h_no_role]
  exact ContractResult.revert_isRevert _

/-! ## SM-P8: confirmBan reverts when already banned -/

theorem confirmBan_revert_already_banned
    (s : ContractState) (node : Address) (reason : Uint256)
    (h_role : s.storageMap2 roleMembers.slot GOVERNANCE_ROLE s.sender = 1)
    (h_banned : s.storageMap banned.slot node = 1) :
    ((confirmBan node reason).run s).fst.isRevert := by
  verity_unfold confirmBan
  simp only [onlyGovernance, msgSender, getMapping2, getMapping, require, bind,
              roleMembers, GOVERNANCE_ROLE, banned,
              h_role, h_banned]
  exact ContractResult.revert_isRevert _

end Contracts.SlashingManager.Proofs
