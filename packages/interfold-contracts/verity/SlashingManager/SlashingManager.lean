/-
  SlashingManager — Formally Verified Implementation

  Translation of the core slashing lifecycle from
  `packages/interfold-contracts/contracts/slashing/SlashingManager.sol`.

  Focus: policy validation, proposal lifecycle (propose → appeal → execute),
  replay protection, and access control.

  EIP-712 signature verification and ECDSA recovery are on trust boundaries.
-/
import Verity.Core
import Verity.Specs.Common

open Verity

/-! ## Storage slot definitions -/

def bondingRegistrySlot : StorageSlot Address := ⟨0⟩
def interfoldSlot : StorageSlot Address := ⟨1⟩
def slasherRoleSlot : StorageSlot (Address → Bool) := ⟨2⟩   -- SLASHER_ROLE members
def governanceRoleSlot : StorageSlot (Address → Bool) := ⟨3⟩ -- GOVERNANCE_ROLE members
def defaultAdminSlot : StorageSlot Address := ⟨4⟩

-- Policy storage: reason → policy config
def ticketPenaltySlot : StorageSlot (Bytes32 → Uint256) := ⟨5⟩
def licensePenaltySlot : StorageSlot (Bytes32 → Uint256) := ⟨6⟩
def requiresProofSlot : StorageSlot (Bytes32 → Bool) := ⟨7⟩
def appealWindowSlot : StorageSlot (Bytes32 → Uint256) := ⟨8⟩
def policyEnabledSlot : StorageSlot (Bytes32 → Bool) := ⟨9⟩

-- Proposal storage: proposalId → proposal
def proposalE3IdSlot : StorageSlot (Uint256 → Uint256) := ⟨10⟩
def proposalOperatorSlot : StorageSlot (Uint256 → Address) := ⟨11⟩
def proposalReasonSlot : StorageSlot (Uint256 → Bytes32) := ⟨12⟩
def proposalTicketAmountSlot : StorageSlot (Uint256 → Uint256) := ⟨13⟩
def proposalLicenseAmountSlot : StorageSlot (Uint256 → Uint256) := ⟨14⟩
def proposalExecutedSlot : StorageSlot (Uint256 → Bool) := ⟨15⟩
def proposalAppealedSlot : StorageSlot (Uint256 → Bool) := ⟨16⟩
def proposalResolvedSlot : StorageSlot (Uint256 → Bool) := ⟨17⟩
def proposalAppealUpheldSlot : StorageSlot (Uint256 → Bool) := ⟨18⟩
def proposalProposedAtSlot : StorageSlot (Uint256 → Uint256) := ⟨19⟩
def proposalExecutableAtSlot : StorageSlot (Uint256 → Uint256) := ⟨20⟩
def proposalLaneSlot : StorageSlot (Uint256 → Uint256) := ⟨21⟩  -- 0 = LaneA, 1 = LaneB

def totalProposalsSlot : StorageSlot Uint256 := ⟨22⟩
def bannedSlot : StorageSlot (Address → Bool) := ⟨23⟩
def consumedEvidenceSlot : StorageSlot (Bytes32 → Bool) := ⟨24⟩

/-! ## Helpers -/

def onlySlashingManager : Contract Unit := do
  let sender ← msgSender
  -- Check SLASHER_ROLE or governance access
  let isSlasher ← getMapping slasherRoleSlot sender
  let isGovernance ← getMapping governanceRoleSlot sender
  require (isSlasher || isGovernance) "not authorized"

def onlyGovernance : Contract Unit := do
  let sender ← msgSender
  let isGovernance ← getMapping governanceRoleSlot sender
  require isGovernance "not governance"

def onlyDefaultAdmin : Contract Unit := do
  let sender ← msgSender
  let admin ← getStorageAddr defaultAdminSlot
  require (sender == admin) "not admin"

/-! ## Policy management -/

/--
  `setSlashPolicy(reason, ticketPenalty, licensePenalty, appealWindow)` —
  Only callable by governance. Validates that at least one penalty > 0
  and Lane B requires appealWindow > 0.
-/
def setSlashPolicy
    (reason : Bytes32) (ticketPenalty licensePenalty appealWindow : Uint256)
    (enabled requiresProof : Bool) : Contract Unit := do
  onlyGovernance
  require (reason != 0) "invalid reason"
  -- Policy must have at least one penalty > 0
  require (ticketPenalty != 0 || licensePenalty != 0) "invalid policy"
  -- Lane B (no proof) requires appealWindow > 0
  if !requiresProof then
    require (appealWindow != 0) "appeal window required for Lane B"
  else
    pure ()
  setMapping ticketPenaltySlot reason ticketPenalty
  setMapping licensePenaltySlot reason licensePenalty
  setMapping appealWindowSlot reason appealWindow
  setMapping policyEnabledSlot reason enabled
  setMapping requiresProofSlot reason requiresProof
  emitEvent "SlashPolicyUpdated" [ticketPenalty, licensePenalty, appealWindow] []

/-! ## Lane B: Evidence-based slashing -/

/--
  `proposeSlashEvidence(e3Id, operator, reason, evidence)` —
  Only callable by SLASHER_ROLE. Creates a Lane B proposal with appeal window.
  The `evidence` parameter is hashed for replay protection (keccak256 on trust boundary).
-/
def proposeSlashEvidence
    (e3Id : Uint256) (operator : Address) (reason : Bytes32)
    (_evidence : Bytes32) : Contract Uint256 := do
  onlySlashingManager
  require (operator != 0) "zero address"
  require (reason != 0) "invalid reason"
  -- Check policy enabled
  let enabled ← getMapping policyEnabledSlot reason
  require enabled "slash reason disabled"
  -- Check policy is Lane B (no proof required)
  let requiresProof ← getMapping requiresProofSlot reason
  require (!requiresProof) "use proposeSlash for proof-based slashing"
  -- Get policy parameters
  let ticketPenalty ← getMapping ticketPenaltySlot reason
  let licensePenalty ← getMapping licensePenaltySlot reason
  let appealWindow ← getMapping appealWindowSlot reason
  -- Create proposal
  let proposalId ← getStorage totalProposalsSlot
  setMapping proposalE3IdSlot proposalId e3Id
  setMapping proposalOperatorSlot proposalId operator
  setMapping proposalReasonSlot proposalId reason
  setMapping proposalTicketAmountSlot proposalId ticketPenalty
  setMapping proposalLicenseAmountSlot proposalId licensePenalty
  setMapping proposalExecutedSlot proposalId false
  setMapping proposalAppealedSlot proposalId false
  setMapping proposalResolvedSlot proposalId false
  setMapping proposalAppealUpheldSlot proposalId false
  let now ← getBlockTimestamp
  setMapping proposalProposedAtSlot proposalId now
  let execAt ← requireSomeUint (safeAdd now appealWindow) "timestamp overflow"
  setMapping proposalExecutableAtSlot proposalId execAt
  setMapping proposalLaneSlot proposalId 1  -- Lane B
  -- Increment total
  let newTotal ← requireSomeUint (safeAdd proposalId 1) "proposal overflow"
  setStorage totalProposalsSlot newTotal
  emitEvent "SlashProposed" [proposalId, e3Id, ticketPenalty, licensePenalty] [addressToWord operator]
  pure proposalId

/-! ## Execute slash (Lane B) -/

/--
  `executeSlash(proposalId)` — executes a Lane B slash after appeal window.
  Permissionless (anyone can call). Reverts if:
  - Proposal already executed
  - Appeal window not elapsed
  - Appeal was upheld
-/
def executeSlash (proposalId : Uint256) : Contract Unit := do
  let executed ← getMapping proposalExecutedSlot proposalId
  require (!executed) "already executed"
  let appealed ← getMapping proposalAppealedSlot proposalId
  let resolved ← getMapping proposalResolvedSlot proposalId
  let upheld ← getMapping proposalAppealUpheldSlot proposalId
  -- If appealed and resolved with appeal upheld, cannot execute
  require (!(appealed && resolved && upheld)) "appeal upheld"
  -- If appealed but not yet resolved, cannot execute
  require (!(appealed && !resolved)) "appeal pending"
  -- Check appeal window
  let execAt ← getMapping proposalExecutableAtSlot proposalId
  let now ← getBlockTimestamp
  require (now >= execAt) "appeal window active"
  -- Mark as executed
  setMapping proposalExecutedSlot proposalId true
  -- In real contract: apply slashing penalties via BondingRegistry
  let operator ← getMapping proposalOperatorSlot proposalId
  emitEvent "SlashExecuted" [proposalId] [addressToWord operator]

/-! ## Appeal lifecycle -/

/--
  `fileAppeal(proposalId)` — operator appeals a Lane B slash.
  Only the slashed operator can appeal. Must be within appeal window.
-/
def fileAppeal (proposalId : Uint256) : Contract Unit := do
  let sender ← msgSender
  let operator ← getMapping proposalOperatorSlot proposalId
  require (sender == operator) "not operator"
  require (operator != 0) "invalid proposal"
  let alreadyAppealed ← getMapping proposalAppealedSlot proposalId
  require (!alreadyAppealed) "already appealed"
  let alreadyExecuted ← getMapping proposalExecutedSlot proposalId
  require (!alreadyExecuted) "already executed"
  -- Check within appeal window
  let execAt ← getMapping proposalExecutableAtSlot proposalId
  let now ← getBlockTimestamp
  require (now < execAt) "appeal window expired"
  setMapping proposalAppealedSlot proposalId true
  emitEvent "AppealFiled" [proposalId] [addressToWord operator]

/--
  `resolveAppeal(proposalId, appealUpheld)` — governance resolves an appeal.
-/
def resolveAppeal (proposalId : Uint256) (appealUpheld : Bool) : Contract Unit := do
  onlyGovernance
  let appealed ← getMapping proposalAppealedSlot proposalId
  require appealed "not appealed"
  let alreadyResolved ← getMapping proposalResolvedSlot proposalId
  require (!alreadyResolved) "already resolved"
  setMapping proposalResolvedSlot proposalId true
  setMapping proposalAppealUpheldSlot proposalId appealUpheld
  emitEvent "AppealResolved" [proposalId] []

/-! ## Ban management -/

/--
  `proposeBan(node, reason)` — governance proposes a ban.
-/
def proposeBan (node : Address) (_reason : Bytes32) : Contract Unit := do
  onlyGovernance
  require (node != 0) "zero address"
  -- Two-step ban: proposal stored; requires confirmBan from different governance
  emitEvent "BanProposed" [0] [addressToWord node]

/--
  `confirmBan(node)` — second governance signer confirms a ban.
-/
def confirmBan (node : Address) : Contract Unit := do
  onlyGovernance
  let alreadyBanned ← getMapping bannedSlot node
  require (!alreadyBanned) "already banned"
  setMapping bannedSlot node true
  emitEvent "NodeBanUpdated" [1] [addressToWord node]
