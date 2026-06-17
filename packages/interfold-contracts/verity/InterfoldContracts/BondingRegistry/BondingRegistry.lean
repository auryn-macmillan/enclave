/-
  BondingRegistry — Verity Formal Verification

  Faithful translation of `contracts/registry/BondingRegistry.sol` using `verity_contract`.

  Modeling decisions:
  - Per-operator state modeled as separate `Address → Uint256` mappings.
  - Boolean storage fields use Uint256 with 1=true, 0=false.
  - `slashingManager` stored as Address (uses getStorageAddr).
  - External calls to CiphernodeRegistry, SlashingManager are trust boundaries.
  - ExitQueueLib queue mechanics simplified to per-operator exit state.
  - SafeERC20 transfers not modeled (oracle).
  - reentrancyGuard not modeled (single-contract scope).
-/
import Contracts.Common

namespace InterfoldContracts

open Verity hiding pure bind
open Verity.EVM.Uint256
open Verity.Stdlib.Math

verity_contract BondingRegistry where
  storage
    licenseBond : Address → Uint256 := slot 0
    exitUnlocksAt : Address → Uint256 := slot 1
    registered : Address → Uint256 := slot 2
    exitRequested : Address → Uint256 := slot 3
    active : Address → Uint256 := slot 4
    slashingManager : Address := slot 5
    licenseRequiredBond : Uint256 := slot 6
    exitDelay : Uint256 := slot 7
    slashedTicketBalance : Uint256 := slot 8
    slashedLicenseBond : Uint256 := slot 9

  function noExitInProgress (operator : Address) : Unit := do
    let req ← getMapping exitRequested operator
    if req == 1 then
      let unlockAt ← getMapping exitUnlocksAt operator
      let t ← blockTimestamp
      require (t >= unlockAt) "exit in progress"
    else
      pure ()

  function registerOperator () : Unit := do
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

  function deregisterOperator () : Unit := do
    let sender ← msgSender
    noExitInProgress sender
    let reg ← getMapping registered sender
    require (reg == 1) "not registered"
    setMapping registered sender 0
    setMapping exitRequested sender 1
    let t ← blockTimestamp
    let delay ← getStorage exitDelay
    let unlockAt ← requireSomeUint (safeAdd t delay) "exit time overflow"
    setMapping exitUnlocksAt sender unlockAt

  function bondLicense (amount : Uint256) : Unit := do
    let sender ← msgSender
    noExitInProgress sender
    require (amount != 0) "zero amount"
    let current ← getMapping licenseBond sender
    let newBond ← requireSomeUint (safeAdd current amount) "bond overflow"
    setMapping licenseBond sender newBond

  function unbondLicense (amount : Uint256) : Unit := do
    let sender ← msgSender
    noExitInProgress sender
    require (amount != 0) "zero amount"
    let current ← getMapping licenseBond sender
    require (current >= amount) "insufficient bond"
    let newBond ← requireSomeUint (safeSub current amount) "bond underflow"
    setMapping licenseBond sender newBond

  function slashTicketBalance (operator : Address, amount : Uint256) : Unit := do
    let sender ← msgSender
    let sm ← getStorageAddr slashingManager
    require (sender == sm) "not slashing manager"
    require (amount != 0) "zero amount"
    let current ← getStorage slashedTicketBalance
    let newSlashed ← requireSomeUint (safeAdd current amount) "slashed overflow"
    setStorage slashedTicketBalance newSlashed

  function slashLicenseBond (operator : Address, amount : Uint256) : Unit := do
    let sender ← msgSender
    let sm ← getStorageAddr slashingManager
    require (sender == sm) "not slashing manager"
    require (amount != 0) "zero amount"
    let bond ← getMapping licenseBond operator
    require (bond >= amount) "insufficient bond"
    let newBond ← requireSomeUint (safeSub bond amount) "bond underflow"
    setMapping licenseBond operator newBond
    let currentSlashed ← getStorage slashedLicenseBond
    let newSlashed ← requireSomeUint (safeAdd currentSlashed amount) "slashed overflow"
    setStorage slashedLicenseBond newSlashed

  function claimExits (maxTicket : Uint256, maxLicense : Uint256) : Unit := do
    let sender ← msgSender
    let exitReq ← getMapping exitRequested sender
    require (exitReq == 1) "no exit requested"
    let unlockAt ← getMapping exitUnlocksAt sender
    let t ← blockTimestamp
    require (t >= unlockAt) "exit not ready"
    setMapping exitRequested sender 0
    setMapping exitUnlocksAt sender 0

namespace BondingRegistry

def onlySlashingManager : Contract Unit := do
  let sender ← msgSender
  let sm ← getStorageAddr slashingManager
  require (sender == sm) "not slashing manager"

end BondingRegistry

end InterfoldContracts
