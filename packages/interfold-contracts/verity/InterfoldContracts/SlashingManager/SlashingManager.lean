/-
  SlashingManager — Verity Formal Verification

  Faithful translation of `contracts/slashing/SlashingManager.sol` using `verity_contract`.

  Modeling decisions:
  - AccessControl roles modeled as separate `Address → Uint256` mappings per role
    (Verity's getMapping2 only supports Address→Address keys).
  - Per-proposal state modeled as `Uint256 → Uint256` (uses getMappingUint/setMappingUint).
  - Proposal operator stored as `Uint256 → Uint256` (operator address as word via addressToWord).
  - `banned` modeled as `Address → Uint256` (1=banned, 0=not).
  - ECDSA, keccak256, external calls — trust boundaries.
-/
import Contracts.Common

namespace InterfoldContracts

open Verity hiding pure bind
open Verity.EVM.Uint256
open Verity.Stdlib.Math

def InterfoldContracts.SlashingManager.GOVERNANCE_ROLE : Uint256 :=
  0x676f7665726e616e63655f726f6c650000000000000000000000000000000000

def InterfoldContracts.SlashingManager.SLASHER_ROLE : Uint256 :=
  0x736c61736865725f726f6c650000000000000000000000000000000000000000

verity_contract SlashingManager where
  storage
    governanceRoleMembers : Address → Uint256 := slot 0
    slasherRoleMembers : Address → Uint256 := slot 1
    banned : Address → Uint256 := slot 2
    proposal_executed : Uint256 → Uint256 := slot 3
    proposal_appealed : Uint256 → Uint256 := slot 4
    proposal_resolved : Uint256 → Uint256 := slot 5
    proposal_upheld : Uint256 → Uint256 := slot 6
    proposal_executableAt : Uint256 → Uint256 := slot 7
    proposal_operator : Uint256 → Uint256 := slot 8
    policy_enabled : Uint256 → Uint256 := slot 9
    policy_ticketPenalty : Uint256 → Uint256 := slot 10
    policy_licensePenalty : Uint256 → Uint256 := slot 11
    policy_appealWindow : Uint256 → Uint256 := slot 12
    policy_requiresProof : Uint256 → Uint256 := slot 13
    totalProposals : Uint256 := slot 14

  function setSlashPolicy (reason : Uint256, ticketPenalty : Uint256, licensePenalty : Uint256, appealWindow : Uint256, enabled : Uint256, requiresProof : Uint256) : Unit := do
    let sender ← msgSender
    let hasRole ← getMapping governanceRoleMembers sender
    require (hasRole == 1) "missing governance role"
    require (ticketPenalty > 0 || licensePenalty > 0) "invalid policy: no penalty"
    if requiresProof == 0 then
      require (appealWindow > 0) "invalid policy: lane B needs appeal window"
    else
      pure ()
    setMappingUint policy_ticketPenalty reason ticketPenalty
    setMappingUint policy_licensePenalty reason licensePenalty
    setMappingUint policy_appealWindow reason appealWindow
    setMappingUint policy_enabled reason enabled
    setMappingUint policy_requiresProof reason requiresProof

  function proposeSlashEvidence (e3Id : Uint256, operator : Address, reason : Uint256, evidence : Uint256) : Unit := do
    let sender ← msgSender
    let hasRole ← getMapping slasherRoleMembers sender
    require (hasRole == 1) "missing slasher role"
    let enabled ← getMappingUint policy_enabled reason
    require (enabled == 1) "slash reason disabled"
    let requiresProof ← getMappingUint policy_requiresProof reason
    require (requiresProof == 0) "lane B requires no proof"
    let appealWindow ← getMappingUint policy_appealWindow reason
    let ts ← blockTimestamp
    let executableAt ← requireSomeUint (safeAdd ts appealWindow) "timestamp overflow"
    let proposalId ← getStorage totalProposals
    setMappingUint proposal_operator proposalId (addressToWord operator)
    setMappingUint proposal_executableAt proposalId executableAt
    setMappingUint proposal_executed proposalId 0
    setMappingUint proposal_appealed proposalId 0
    setMappingUint proposal_resolved proposalId 0
    setMappingUint proposal_upheld proposalId 0
    let nextId ← requireSomeUint (safeAdd proposalId 1) "proposal overflow"
    setStorage totalProposals nextId

  function executeSlash (proposalId : Uint256) : Unit := do
    let executed ← getMappingUint proposal_executed proposalId
    require (executed == 0) "already executed"
    let appealed ← getMappingUint proposal_appealed proposalId
    if appealed == 1 then
      let resolved ← getMappingUint proposal_resolved proposalId
      require (resolved == 1) "appeal pending"
      let upheld ← getMappingUint proposal_upheld proposalId
      require (upheld == 0) "appeal upheld"
    else
      pure ()
    let ts ← blockTimestamp
    let executableAt ← getMappingUint proposal_executableAt proposalId
    require (ts >= executableAt) "appeal window active"
    setMappingUint proposal_executed proposalId 1

  function fileAppeal (proposalId : Uint256) : Unit := do
    let sender ← msgSender
    let opWord ← getMappingUint proposal_operator proposalId
    require (opWord == addressToWord sender) "unauthorized"
    let executed ← getMappingUint proposal_executed proposalId
    require (executed == 0) "already executed"
    let appealed ← getMappingUint proposal_appealed proposalId
    require (appealed == 0) "already appealed"
    let ts ← blockTimestamp
    let executableAt ← getMappingUint proposal_executableAt proposalId
    require (ts < executableAt) "appeal window expired"
    setMappingUint proposal_appealed proposalId 1

  function resolveAppeal (proposalId : Uint256, upheld : Uint256) : Unit := do
    let sender ← msgSender
    let hasRole ← getMapping governanceRoleMembers sender
    require (hasRole == 1) "missing governance role"
    let appealed ← getMappingUint proposal_appealed proposalId
    require (appealed == 1) "not appealed"
    let resolved ← getMappingUint proposal_resolved proposalId
    require (resolved == 0) "already resolved"
    setMappingUint proposal_resolved proposalId 1
    setMappingUint proposal_upheld proposalId upheld

  function confirmBan (node : Address, reason : Uint256) : Unit := do
    let sender ← msgSender
    let hasRole ← getMapping governanceRoleMembers sender
    require (hasRole == 1) "missing governance role"
    let isBanned ← getMapping banned node
    require (isBanned == 0) "already banned"
    setMapping banned node 1

  function isBanned (node : Address) : Uint256 := do
    let result ← getMapping banned node
    return result

namespace SlashingManager

def onlyGovernance : Contract Unit := do
  let sender ← msgSender
  let result ← getMapping governanceRoleMembers sender
  require (result == 1) "missing governance role"

def onlySlasher : Contract Unit := do
  let sender ← msgSender
  let result ← getMapping slasherRoleMembers sender
  require (result == 1) "missing slasher role"

end SlashingManager

end InterfoldContracts
