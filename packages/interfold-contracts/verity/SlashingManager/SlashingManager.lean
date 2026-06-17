/-
  SlashingManager — Verity Formal Verification

  Faithful translation of `contracts/slashing/SlashingManager.sol` using `verity_contract`.

  Modeling decisions:
  - AccessControl roles modeled as `storageMap2` (role Uint256 → address → Uint256 1/0),
    matching Solidity's `mapping(bytes32 => RoleData)` where `RoleData` has
    `mapping(address => bool) members`. Same pattern as InterfoldToken.
  - Role IDs are opaque Uint256 constants. GOVERNANCE_ROLE and SLASHER_ROLE are
    keccak256 hashes — their actual values don't matter for the proofs.
  - Per-proposal state modeled as `storageMapUint` (Uint256 → Uint256) keyed by proposalId.
  - `banned` modeled as `storageMap` (Address → Uint256, 1=banned, 0=not).
  - ECDSA signature verification is NOT modeled (oracle).
  - keccak256 for evidence hashing is NOT modeled (axiomatized).
  - External calls to BondingRegistry are NOT modeled (oracle).
  - Proposal operator is modeled as `storageMap2` (proposalId → Address → Uint256) for
    faithful access control in `fileAppeal`.

  Proof objectives (see PROOF_OBJECTIVES.md):
  - SM-P1: setSlashPolicy reverts when ticketPenalty = 0 && licensePenalty = 0
  - SM-P2: setSlashPolicy reverts when !requiresProof && appealWindow = 0
  - SM-P3: executeSlash reverts when proposal already executed
  - SM-P4: executeSlash reverts when block.timestamp < executableAt
  - SM-P5: fileAppeal reverts when msg.sender ≠ proposal.operator
  - SM-P6: fileAppeal reverts when block.timestamp >= executableAt
  - SM-P7: resolveAppeal reverts when caller lacks GOVERNANCE_ROLE
  - SM-P8: confirmBan reverts when already banned
-/
import Contracts.Common

namespace Contracts.SlashingManager

open Verity hiding pure bind
open Verity.EVM.Uint256

/-! ## Role constants (matching Solidity keccak256 hashes) -/

-- `GOVERNANCE_ROLE = keccak256("GOVERNANCE_ROLE")` — opaque constant
def GOVERNANCE_ROLE : Uint256 := 0x676f7665726e616e63655f726f6c650000000000000000000000000000000000

-- `SLASHER_ROLE = keccak256("SLASHER_ROLE")` — opaque constant
def SLASHER_ROLE : Uint256 := 0x736c61736865725f726f6c650000000000000000000000000000000000000000

/-! ## Contract -/

verity_contract SlashingManager where
  storage
    -- AccessControl: roleMembers[role][account] = 1 if account has role
    roleMembers : Uint256 -> Address -> Uint256 := slot 0

    -- Ban state: banned[node] = 1 if banned
    banned : Address -> Uint256 := slot 1

    -- Per-proposal state (Uint256 → Uint256, keyed by proposalId)
    proposal_executed : Uint256 -> Uint256 := slot 2
    proposal_appealed : Uint256 -> Uint256 := slot 3
    proposal_resolved : Uint256 -> Uint256 := slot 4
    proposal_upheld : Uint256 -> Uint256 := slot 5
    proposal_executableAt : Uint256 -> Uint256 := slot 6

    -- Per-proposal operator ownership (proposalId → Address → Uint256 1/0)
    proposal_operator : Uint256 -> Address -> Uint256 := slot 7

    -- SlashPolicy storage (per reason hash)
    policy_enabled : Uint256 -> Uint256 := slot 8
    policy_ticketPenalty : Uint256 -> Uint256 := slot 9
    policy_licensePenalty : Uint256 -> Uint256 := slot 10
    policy_appealWindow : Uint256 -> Uint256 := slot 11
    policy_requiresProof : Uint256 -> Uint256 := slot 12

    -- Total proposals counter
    totalProposals : Uint256 := slot 13

  -- Guard: check that caller has GOVERNANCE_ROLE
  function onlyGovernance : Unit := do
    let sender ← msgSender
    let hasRole ← getMapping2 roleMembers GOVERNANCE_ROLE sender
    require (hasRole == 1) "missing governance role"

  -- Guard: check that caller has SLASHER_ROLE
  function onlySlasher : Unit := do
    let sender ← msgSender
    let hasRole ← getMapping2 roleMembers SLASHER_ROLE sender
    require (hasRole == 1) "missing slasher role"

  -- setSlashPolicy(reason, ticketPenalty, licensePenalty, appealWindow, enabled, requiresProof)
  -- Only callable by GOVERNANCE_ROLE.
  -- Validates: ticketPenalty > 0 OR licensePenalty > 0 (SM-P1)
  -- Validates: if !requiresProof then appealWindow > 0 (SM-P2, Lane B needs appeal window)
  function setSlashPolicy
      (reason : Uint256) (ticketPenalty : Uint256) (licensePenalty : Uint256)
      (appealWindow : Uint256) (enabled : Uint256) (requiresProof : Uint256) : Unit := do
    onlyGovernance
    require (ticketPenalty > 0 || licensePenalty > 0) "invalid policy: no penalty"
    -- Evidence-based (Lane B) policies require a non-zero appealWindow
    if requiresProof == 0 then
      require (appealWindow > 0) "invalid policy: lane B needs appeal window"
    else
      pure ()
    setMapping policy_ticketPenalty reason ticketPenalty
    setMapping policy_licensePenalty reason licensePenalty
    setMapping policy_appealWindow reason appealWindow
    setMapping policy_enabled reason enabled
    setMapping policy_requiresProof reason requiresProof
    emitEvent "SlashPolicyUpdated" [reason] []

  -- proposeSlashEvidence(e3Id, operator, reason, evidence)
  -- Lane B: evidence-based slash. Only callable by SLASHER_ROLE.
  -- Creates a deferred proposal with executableAt = now + appealWindow.
  -- Modeled without keccak256 (oracle) and without BondingRegistry calls (oracle).
  function proposeSlashEvidence
      (e3Id : Uint256) (operator : Address) (reason : Uint256) (evidence : Uint256) : Unit := do
    onlySlasher
    let enabled ← getMapping policy_enabled reason
    require (enabled == 1) "slash reason disabled"
    let requiresProof ← getMapping policy_requiresProof reason
    require (requiresProof == 0) "lane B requires no proof"
    -- Obtain appeal window from policy
    let appealWindow ← getMapping policy_appealWindow reason
    -- Create proposal with executableAt = now + appealWindow
    let ts ← blockTimestamp
    let executableAt ← requireSomeUint (safeAdd ts appealWindow) "timestamp overflow"
    let proposalId ← getStorage totalProposals
    -- Store operator ownership
    setMapping2 proposal_operator proposalId operator 1
    -- Store proposal state
    setMapping proposal_executableAt proposalId executableAt
    setMapping proposal_executed proposalId 0
    setMapping proposal_appealed proposalId 0
    setMapping proposal_resolved proposalId 0
    setMapping proposal_upheld proposalId 0
    -- Increment totalProposals
    let nextId ← requireSomeUint (safeAdd proposalId 1) "proposal overflow"
    setStorage totalProposals nextId
    emitEvent "SlashProposed" [proposalId] [addressToWord operator]

  -- executeSlash(proposalId)
  -- Permissionless. Executes a deferred proposal after the appeal window.
  -- Reverts if: already executed (SM-P3), appeal active/unresolved, or ts < executableAt (SM-P4).
  function executeSlash (proposalId : Uint256) : Unit := do
    let executed ← getMapping proposal_executed proposalId
    require (executed == 0) "already executed"
    -- Appeal check: if appealed, must be resolved and NOT upheld
    let appealed ← getMapping proposal_appealed proposalId
    if appealed == 1 then
      let resolved ← getMapping proposal_resolved proposalId
      require (resolved == 1) "appeal pending"
      let upheld ← getMapping proposal_upheld proposalId
      require (upheld == 0) "appeal upheld"
    else
      pure ()
    -- Timestamp check: must be past or at executableAt
    let ts ← blockTimestamp
    let executableAt ← getMapping proposal_executableAt proposalId
    require (ts >= executableAt) "appeal window active"
    setMapping proposal_executed proposalId 1
    emitEvent "SlashExecuted" [proposalId] []

  -- fileAppeal(proposalId)
  -- Only the accused operator can appeal. Must be within the appeal window.
  -- Reverts if: sender != operator (SM-P5), already executed, already appealed, or
  --   ts >= executableAt (SM-P6, window expired).
  function fileAppeal (proposalId : Uint256) : Unit := do
    let sender ← msgSender
    let isOp ← getMapping2 proposal_operator proposalId sender
    require (isOp == 1) "unauthorized"
    let executed ← getMapping proposal_executed proposalId
    require (executed == 0) "already executed"
    let appealed ← getMapping proposal_appealed proposalId
    require (appealed == 0) "already appealed"
    let ts ← blockTimestamp
    let executableAt ← getMapping proposal_executableAt proposalId
    require (ts < executableAt) "appeal window expired"
    setMapping proposal_appealed proposalId 1
    emitEvent "AppealFiled" [proposalId] []

  -- resolveAppeal(proposalId, upheld)
  -- Only callable by GOVERNANCE_ROLE (SM-P7). Must be appealed and not yet resolved.
  function resolveAppeal (proposalId : Uint256) (upheld : Uint256) : Unit := do
    onlyGovernance
    let appealed ← getMapping proposal_appealed proposalId
    require (appealed == 1) "not appealed"
    let resolved ← getMapping proposal_resolved proposalId
    require (resolved == 0) "already resolved"
    setMapping proposal_resolved proposalId 1
    setMapping proposal_upheld proposalId upheld
    emitEvent "AppealResolved" [proposalId] []

  -- proposeBan(node, reason)
  -- Only callable by GOVERNANCE_ROLE. Two-step ban flow: propose then confirm.
  function proposeBan (node : Address) (reason : Uint256) : Unit := do
    onlyGovernance
    -- Oracle: pending ban storage omitted (not needed for SM-P8)
    emitEvent "BanProposed" [reason] [addressToWord node]

  -- confirmBan(node, reason)
  -- Only callable by GOVERNANCE_ROLE. Sets banned[node] = true.
  -- Reverts if already banned (SM-P8).
  function confirmBan (node : Address) (reason : Uint256) : Unit := do
    onlyGovernance
    let isBanned ← getMapping banned node
    require (isBanned == 0) "already banned"
    setMapping banned node 1
    emitEvent "NodeBanUpdated" [1] [addressToWord node]

  -- isBanned(node): view function returning banned[node] (1=banned, 0=not)
  function isBanned (node : Address) : Uint256 := do
    getMapping banned node

end Contracts.SlashingManager
