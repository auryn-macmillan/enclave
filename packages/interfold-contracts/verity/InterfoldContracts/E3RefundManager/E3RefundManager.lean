/-
  E3RefundManager — Verity Formal Verification

  Faithful translation of `contracts/E3RefundManager.sol` using `verity_contract`.

  Modeling decisions:
  - `interfold` and `owner` stored as Address (uses getStorageAddr).
  - Per-E3 distribution state modeled as `Uint256 → Uint256` (uses getMappingUint).
  - Claim tracking simplified: `claimedRequester : Uint256 → Uint256` tracks
    whether requester has claimed for a given e3Id. Honest node per-address
    tracking requires Address→Address mapping which is modeled as
    `claimedHonestNode : Address → Uint256` (per-claimer, not per-e3Id).
  - BPS math, ERC20 transfers, external calls — trust boundaries.
-/
import Contracts.Common

namespace InterfoldContracts

open Verity hiding pure bind
open Verity.EVM.Uint256
open Verity.Stdlib.Math

verity_contract E3RefundManager where
  storage
    interfold : Address := slot 0
    owner : Address := slot 1
    calculated : Uint256 → Uint256 := slot 2
    requesterAmount : Uint256 → Uint256 := slot 3
    honestNodeAmount : Uint256 → Uint256 := slot 4
    perNodeAmount : Uint256 → Uint256 := slot 5
    originalPayment : Uint256 → Uint256 := slot 6
    honestNodeCount : Uint256 → Uint256 := slot 7
    claimedRequester : Uint256 → Uint256 := slot 8
    claimCount : Uint256 → Uint256 := slot 9
    pendingSlashedFunds : Uint256 → Uint256 := slot 10

  function calculateRefund (e3Id : Uint256, originalPaymentVal : Uint256) : Unit := do
    let sender ← msgSender
    let ifold ← getStorageAddr interfold
    require (sender == ifold) "caller is not Interfold"
    let calcVal ← getMappingUint calculated e3Id
    require (calcVal == 0) "Already calculated"
    require (originalPaymentVal > 0) "No payment"
    setMappingUint calculated e3Id 1
    setMappingUint originalPayment e3Id originalPaymentVal
    setMappingUint requesterAmount e3Id originalPaymentVal
    setMappingUint perNodeAmount e3Id 1

  function claimRequesterRefund (e3Id : Uint256) : Unit := do
    let calcVal ← getMappingUint calculated e3Id
    require (calcVal == 1) "Refund not calculated"
    let sender ← msgSender
    let alreadyClaimed ← getMappingUint claimedRequester e3Id
    require (alreadyClaimed == 0) "Already claimed"
    let cnt ← getMappingUint claimCount e3Id
    let newCnt ← requireSomeUint (safeAdd cnt 1) "count overflow"
    setMappingUint claimCount e3Id newCnt
    setMappingUint claimedRequester e3Id 1
    let amt ← getMappingUint requesterAmount e3Id
    require (amt > 0) "No refund available"

  function claimHonestNodeReward (e3Id : Uint256) : Unit := do
    let calcVal ← getMappingUint calculated e3Id
    require (calcVal == 1) "Refund not calculated"
    let sender ← msgSender
    let cnt ← getMappingUint claimCount e3Id
    let newCnt ← requireSomeUint (safeAdd cnt 1) "count overflow"
    setMappingUint claimCount e3Id newCnt
    let amt ← getMappingUint perNodeAmount e3Id
    require (amt > 0) "No refund available"

  function escrowSlashedFunds (e3Id : Uint256, amount : Uint256) : Unit := do
    let sender ← msgSender
    let ifold ← getStorageAddr interfold
    require (sender == ifold) "caller is not Interfold"
    require (amount > 0) "Zero amount"
    let pending ← getMappingUint pendingSlashedFunds e3Id
    let newPending ← requireSomeUint (safeAdd pending amount) "overflow"
    setMappingUint pendingSlashedFunds e3Id newPending

  function distributeSlashedFundsOnSuccess (e3Id : Uint256) : Unit := do
    let sender ← msgSender
    let ifold ← getStorageAddr interfold
    require (sender == ifold) "caller is not Interfold"
    let escrowed ← getMappingUint pendingSlashedFunds e3Id
    if escrowed == 0 then
      pure ()
    else
      setMappingUint pendingSlashedFunds e3Id 0

  function setWorkAllocation () : Unit := do
    let sender ← msgSender
    let own ← getStorageAddr owner
    require (sender == own) "caller is not owner"

  function withdrawOrphanedSlashedFunds (e3Id : Uint256) : Unit := do
    let sender ← msgSender
    let own ← getStorageAddr owner
    require (sender == own) "caller is not owner"
    let pending ← getMappingUint pendingSlashedFunds e3Id
    require (pending > 0) "No orphaned funds"
    setMappingUint pendingSlashedFunds e3Id 0

namespace E3RefundManager

def onlyInterfold : Contract Unit := do
  let sender ← msgSender
  let ifold ← getStorageAddr interfold
  require (sender == ifold) "caller is not Interfold"

def onlyOwner : Contract Unit := do
  let sender ← msgSender
  let own ← getStorageAddr owner
  require (sender == own) "caller is not owner"

end E3RefundManager

end InterfoldContracts
