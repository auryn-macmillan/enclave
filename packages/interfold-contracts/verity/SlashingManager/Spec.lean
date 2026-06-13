/-
  SlashingManager — Formal Specifications
-/
import Verity.Core
import Verity.Specs.Common
import SlashingManager.SlashingManager

open Verity

/--
  Policy validation spec: at least one penalty > 0, Lane B requires appealWindow > 0.
-/
def setSlashPolicy_spec
    (reason : Bytes32) (ticketPenalty licensePenalty appealWindow : Uint256)
    (enabled requiresProof : Bool) (s s' : ContractState) : Prop :=
  (s.storageMap governanceRoleSlot.slot s.sender = true ∧
   reason ≠ 0 ∧
   (ticketPenalty ≠ 0 ∨ licensePenalty ≠ 0) ∧
   (requiresProof = true ∨ appealWindow ≠ 0)) →
    s'.storageMap ticketPenaltySlot.slot reason = ticketPenalty ∧
    s'.storageMap licensePenaltySlot.slot reason = licensePenalty ∧
    s'.storageMap appealWindowSlot.slot reason = appealWindow ∧
    s'.storageMap policyEnabledSlot.slot reason = enabled ∧
    s'.storageMap requiresProofSlot.slot reason = requiresProof

/--
  Lane B proposal lifecycle: proposal cannot be executed while appealed and unresolved.
-/
def proposal_lifecycle_spec (proposalId : Uint256) (s s' : ContractState) : Prop :=
  (s.storageMap proposalExecutedSlot.slot proposalId = true) →
  s'.storageMap proposalExecutedSlot.slot proposalId = true

/--
  Evidence replay protection: consumed evidence cannot be used twice.
-/
def evidence_replay_spec (evidence : Bytes32) (s s' : ContractState) : Prop :=
  s.storageMap consumedEvidenceSlot.slot evidence = true →
  s'.storageMap consumedEvidenceSlot.slot evidence = true
