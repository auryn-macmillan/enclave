/-
  SlashingManager — Machine-Checked Proofs

  Proves policy validation, proposal lifecycle state machine,
  and access control enforcement.
-/
import Verity.Core
import Verity.Specs.Common
import SlashingManager.SlashingManager
import SlashingManager.Spec

open Verity

set_option maxHeartbeats 400000

/-! ## Policy validation -/

theorem setSlashPolicy_reverts_zero_reason
    (s : ContractState) (tp lp aw : Uint256) (enabled rp : Bool)
    (h_gov : s.storageMap governanceRoleSlot.slot s.sender = true) :
    ((setSlashPolicy 0 tp lp aw enabled rp).run s).fst.isRevert := by
  unfold setSlashPolicy onlyGovernance
  simp [msgSender, getMapping, governanceRoleSlot, require, bind, h_gov]

theorem setSlashPolicy_reverts_zero_penalty
    (s : ContractState) (reason : Bytes32) (aw : Uint256) (enabled rp : Bool)
    (h_gov : s.storageMap governanceRoleSlot.slot s.sender = true)
    (h_reason : reason ≠ 0) :
    ((setSlashPolicy reason 0 0 aw enabled rp).run s).fst.isRevert := by
  unfold setSlashPolicy onlyGovernance
  simp [msgSender, getMapping, governanceRoleSlot, require, bind, h_gov, h_reason]

theorem setSlashPolicy_reverts_lane_b_no_appeal_window
    (s : ContractState) (reason : Bytes32) (tp lp : Uint256) (enabled : Bool)
    (h_gov : s.storageMap governanceRoleSlot.slot s.sender = true)
    (h_reason : reason ≠ 0)
    (h_penalty : tp ≠ 0 ∨ lp ≠ 0) :
    ((setSlashPolicy reason tp lp 0 enabled false).run s).fst.isRevert := by
  unfold setSlashPolicy onlyGovernance
  simp [msgSender, getMapping, governanceRoleSlot, require, bind, h_gov, h_reason, h_penalty]

/-! ## Proposal lifecycle -/

theorem executeSlash_reverts_already_executed
    (s : ContractState) (proposalId : Uint256)
    (h_executed : s.storageMap proposalExecutedSlot.slot proposalId = true) :
    ((executeSlash proposalId).run s).fst.isRevert := by
  unfold executeSlash
  simp [getMapping, proposalExecutedSlot, require, bind, h_executed]

theorem executeSlash_reverts_appeal_upheld
    (s : ContractState) (proposalId : Uint256)
    (h_not_executed : s.storageMap proposalExecutedSlot.slot proposalId = false)
    (h_appealed : s.storageMap proposalAppealedSlot.slot proposalId = true)
    (h_resolved : s.storageMap proposalResolvedSlot.slot proposalId = true)
    (h_upheld : s.storageMap proposalAppealUpheldSlot.slot proposalId = true) :
    ((executeSlash proposalId).run s).fst.isRevert := by
  unfold executeSlash
  simp [getMapping, proposalExecutedSlot, proposalAppealedSlot,
        proposalResolvedSlot, proposalAppealUpheldSlot,
        require, bind, h_not_executed, h_appealed, h_resolved, h_upheld]

theorem executeSlash_reverts_appeal_pending
    (s : ContractState) (proposalId : Uint256)
    (h_not_executed : s.storageMap proposalExecutedSlot.slot proposalId = false)
    (h_appealed : s.storageMap proposalAppealedSlot.slot proposalId = true)
    (h_not_resolved : s.storageMap proposalResolvedSlot.slot proposalId = false) :
    ((executeSlash proposalId).run s).fst.isRevert := by
  unfold executeSlash
  simp [getMapping, proposalExecutedSlot, proposalAppealedSlot,
        proposalResolvedSlot,
        require, bind, h_not_executed, h_appealed, h_not_resolved]

/-! ## Appeal access control -/

theorem fileAppeal_reverts_non_operator
    (s : ContractState) (proposalId : Uint256)
    (h_operator : s.storageMap proposalOperatorSlot.slot proposalId ≠ 0)
    (h_not_operator : s.sender ≠ s.storageMap proposalOperatorSlot.slot proposalId) :
    ((fileAppeal proposalId).run s).fst.isRevert := by
  unfold fileAppeal
  simp [msgSender, getMapping,
        proposalOperatorSlot, proposalAppealedSlot,
        require, bind, h_not_operator]

theorem fileAppeal_reverts_already_appealed
    (s : ContractState) (proposalId : Uint256)
    (h_operator : s.sender = s.storageMap proposalOperatorSlot.slot proposalId)
    (h_operator_nonzero : s.storageMap proposalOperatorSlot.slot proposalId ≠ 0)
    (h_already_appealed : s.storageMap proposalAppealedSlot.slot proposalId = true) :
    ((fileAppeal proposalId).run s).fst.isRevert := by
  unfold fileAppeal
  simp [msgSender, getMapping,
        proposalOperatorSlot, proposalAppealedSlot,
        require, bind, h_operator, h_already_appealed]

/-! ## Resolve appeal access control -/

theorem resolveAppeal_reverts_non_governance
    (s : ContractState) (proposalId : Uint256) (upheld : Bool)
    (h_not_gov : s.storageMap governanceRoleSlot.slot s.sender = false) :
    ((resolveAppeal proposalId upheld).run s).fst.isRevert := by
  unfold resolveAppeal onlyGovernance
  simp [msgSender, getMapping, governanceRoleSlot, require, bind, h_not_gov]

theorem resolveAppeal_reverts_already_resolved
    (s : ContractState) (proposalId : Uint256) (upheld : Bool)
    (h_gov : s.storageMap governanceRoleSlot.slot s.sender = true)
    (h_appealed : s.storageMap proposalAppealedSlot.slot proposalId = true)
    (h_resolved : s.storageMap proposalResolvedSlot.slot proposalId = true) :
    ((resolveAppeal proposalId upheld).run s).fst.isRevert := by
  unfold resolveAppeal onlyGovernance
  simp [msgSender, getMapping,
        governanceRoleSlot, proposalAppealedSlot, proposalResolvedSlot,
        require, bind, h_gov, h_appealed, h_resolved]

/-! ## Ban access control -/

theorem proposeBan_reverts_non_governance
    (s : ContractState) (node : Address) (reason : Bytes32)
    (h_not_gov : s.storageMap governanceRoleSlot.slot s.sender = false) :
    ((proposeBan node reason).run s).fst.isRevert := by
  unfold proposeBan onlyGovernance
  simp [msgSender, getMapping, governanceRoleSlot, require, bind, h_not_gov]

theorem confirmBan_reverts_already_banned
    (s : ContractState) (node : Address)
    (h_gov : s.storageMap governanceRoleSlot.slot s.sender = true)
    (h_banned : s.storageMap bannedSlot.slot node = true) :
    ((confirmBan node).run s).fst.isRevert := by
  unfold confirmBan onlyGovernance
  simp [msgSender, getMapping,
        governanceRoleSlot, bannedSlot,
        require, bind, h_gov, h_banned]
