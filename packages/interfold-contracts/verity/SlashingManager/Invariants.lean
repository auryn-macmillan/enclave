/-
  SlashingManager — Contract Invariants

  Proposal lifecycle and access control invariants.
-/
import Verity.Core
import SlashingManager.SlashingManager

open Verity

/--
  **Proposal lifecycle monotonicity**: Once executed, a proposal stays executed.
  Once resolved, an appeal stays resolved.
-/
def inv_proposal_monotonicity (proposalId : Uint256) (s_old s_new : ContractState) : Prop :=
  (s_old.storageMap proposalExecutedSlot.slot proposalId = true →
   s_new.storageMap proposalExecutedSlot.slot proposalId = true) ∧
  (s_old.storageMap proposalResolvedSlot.slot proposalId = true →
   s_new.storageMap proposalResolvedSlot.slot proposalId = true)

/--
  **Ban idempotency**: Once banned, a node stays banned (no unban in this model).
  The real contract allows unban via `unbanNode()` (GOVERNANCE_ROLE).
-/
def inv_ban_persistence (node : Address) (s_old s_new : ContractState) : Prop :=
  s_old.storageMap bannedSlot.slot node = true →
  s_new.storageMap bannedSlot.slot node = true

/--
  **Evidence replay protection**: Once evidence is consumed, it cannot be reused.
-/
def inv_evidence_replay (evidence : Bytes32) (s_old s_new : ContractState) : Prop :=
  s_old.storageMap consumedEvidenceSlot.slot evidence = true →
  s_new.storageMap consumedEvidenceSlot.slot evidence = true

/--
  **Policy validation**: For every enabled slash reason, at least one penalty is non-zero.
-/
def inv_policy_valid (reason : Bytes32) (s : ContractState) : Prop :=
  s.storageMap policyEnabledSlot.slot reason = true →
  (s.storageMap ticketPenaltySlot.slot reason ≠ 0 ∨
   s.storageMap licensePenaltySlot.slot reason ≠ 0)
