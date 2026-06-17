/-
  BondingRegistry — Verity Formal Verification

  Faithful translation of `contracts/registry/BondingRegistry.sol` using `verity_contract`.

  Modeling decisions:
  - Per-operator state struct { licenseBond, exitUnlocksAt, registered, exitRequested, active }
    is modeled as five separate `Address → Uint256` mappings, one per field.
  - Boolean storage fields use Uint256 with 1=true, 0=false.
  - `onlySlashingManager`: checks `msg.sender == slashingManager`.
    slashingManager is stored as Address.
  - `noExitInProgress(operator)`: checks `exitRequested[op] == 1 && block.timestamp < exitUnlocksAt[op]`
    and reverts. Modeled faithfully: `getBlockTimestamp` reads the current block time.
  - External calls to `CiphernodeRegistry`, `SlashingManager.isBanned`,
    `SlashingManager.hasOpenLaneBProposal` are NOT modeled (oracle trust boundaries).
  - `ExitQueueLib` queue mechanics are NOT modeled; exit state is simplified to per-operator
    `exitRequested` / `exitUnlocksAt` and global `slashedTicketBalance` / `slashedLicenseBond`.
  - `SafeERC20` transfers are NOT modeled (oracle).
  - `_updateOperatorStatus` is NOT modeled (oracle — depends on external token balances).
  - `reentrancyGuard` is NOT modeled (not needed for per-transition proofs).

  Proof objectives (see PROOF_OBJECTIVES.md):
  - BR-P1: `slashTicketBalance` and `slashLicenseBond` revert when sender ≠ slashingManager
  - BR-P2: `registerOperator` reverts when already registered
  - BR-P3: `registerOperator` reverts when licenseBond < licenseRequiredBond
  - BR-P4: `registerOperator` clears previous exit request before checking preconditions
  - BR-P5: `deregisterOperator` reverts when not registered
  - BR-P6: `bondLicense` increments `licenseBond[op]` by amount
  - BR-P7: `unbondLicense` reverts when `licenseBond[op] < amount`
  - BR-P8: `unbondLicense` decrements `licenseBond[op]` by amount
  - BR-P9: `deregisterOperator` sets `exitUnlocksAt = block.timestamp + exitDelay`
-/
import Contracts.Common

namespace Contracts.BondingRegistry

open Verity hiding pure bind
open Verity.EVM.Uint256

verity_contract BondingRegistry where
  storage
    licenseBond : Address -> Uint256 := slot 0
    exitUnlocksAt : Address -> Uint256 := slot 1
    registered : Address -> Uint256 := slot 2
    exitRequested : Address -> Uint256 := slot 3
    active : Address -> Uint256 := slot 4
    slashingManager : Address := slot 5
    licenseRequiredBond : Uint256 := slot 6
    exitDelay : Uint256 := slot 7
    slashedTicketBalance : Uint256 := slot 8
    slashedLicenseBond : Uint256 := slot 9

  function onlySlashingManager : Unit := do
    let sender ← msgSender
    let sm ← getStorage slashingManager
    require (sender == sm) "not slashing manager"

  function noExitInProgress (operator : Address) : Unit := do
    let req ← getMapping exitRequested operator
    if req == 1 then
      let unlockAt ← getMapping exitUnlocksAt operator
      let t ← getBlockTimestamp
      require (t >= unlockAt) "exit in progress"
    else
      pure ()

  function registerOperator : Unit := do
    let sender ← msgSender
    noExitInProgress sender
    let exitReq ← getMapping exitRequested sender
    if exitReq == 1 then
      setMapping exitRequested sender 0
      setMapping exitUnlocksAt sender 0
    else
      pure ()
    let reg ← getMapping registered sender
    require (reg == 0) "already registered"
    let bond ← getMapping licenseBond sender
    let reqBond ← getStorage licenseRequiredBond
    require (bond >= reqBond) "insufficient license bond"
    setMapping registered sender 1
    emitEvent "CiphernodeRegistered" [] [addressToWord sender]

  function deregisterOperator : Unit := do
    let sender ← msgSender
    noExitInProgress sender
    let reg ← getMapping registered sender
    require (reg == 1) "not registered"
    setMapping registered sender 0
    setMapping exitRequested sender 1
    let t ← getBlockTimestamp
    let delay ← getStorage exitDelay
    let unlockAt ← requireSomeUint (safeAdd t delay) "exit time overflow"
    setMapping exitUnlocksAt sender unlockAt
    emitEvent "CiphernodeDeregistrationRequested" [unlockAt] [addressToWord sender]

  function bondLicense (amount : Uint256) : Unit := do
    let sender ← msgSender
    noExitInProgress sender
    require (amount != 0) "zero amount"
    let current ← getMapping licenseBond sender
    let newBond ← requireSomeUint (safeAdd current amount) "bond overflow"
    setMapping licenseBond sender newBond
    emitEvent "LicenseBondUpdated" [amount] [addressToWord sender]

  function unbondLicense (amount : Uint256) : Unit := do
    let sender ← msgSender
    noExitInProgress sender
    require (amount != 0) "zero amount"
    let current ← getMapping licenseBond sender
    require (current >= amount) "insufficient bond"
    let newBond ← requireSomeUint (safeSub current amount) "bond underflow"
    setMapping licenseBond sender newBond
    emitEvent "LicenseBondUpdated" [amount] [addressToWord sender]

  function slashTicketBalance (operator : Address) (amount : Uint256) : Unit := do
    onlySlashingManager
    require (amount != 0) "zero amount"
    let current ← getStorage slashedTicketBalance
    let newSlashed ← requireSomeUint (safeAdd current amount) "slashed overflow"
    setStorage slashedTicketBalance newSlashed
    emitEvent "TicketBalanceSlashed" [amount] [addressToWord operator]

  function slashLicenseBond (operator : Address) (amount : Uint256) : Unit := do
    onlySlashingManager
    require (amount != 0) "zero amount"
    let bond ← getMapping licenseBond operator
    require (bond >= amount) "insufficient bond"
    let newBond ← requireSomeUint (safeSub bond amount) "bond underflow"
    setMapping licenseBond operator newBond
    let currentSlashed ← getStorage slashedLicenseBond
    let newSlashed ← requireSomeUint (safeAdd currentSlashed amount) "slashed overflow"
    setStorage slashedLicenseBond newSlashed
    emitEvent "LicenseBondSlashed" [amount] [addressToWord operator]

  function claimExits (maxTicket : Uint256) (maxLicense : Uint256) : Unit := do
    let sender ← msgSender
    let exitReq ← getMapping exitRequested sender
    require (exitReq == 1) "no exit requested"
    let unlockAt ← getMapping exitUnlocksAt sender
    let t ← getBlockTimestamp
    require (t >= unlockAt) "exit not ready"
    setMapping exitRequested sender 0
    setMapping exitUnlocksAt sender 0
    emitEvent "ExitsClaimed" [maxTicket, maxLicense] [addressToWord sender]

end Contracts.BondingRegistry
