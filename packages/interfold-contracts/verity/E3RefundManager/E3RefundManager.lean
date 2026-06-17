/-
  E3RefundManager — Verity Formal Verification

  Faithful translation of `contracts/E3RefundManager.sol` using `verity_contract`.

  Modeling decisions:
  - `onlyInterfold` guard: checks msg.sender == interfold address slot
  - `onlyOwner` guard: checks msg.sender == owner address slot
  - Per-E3 distribution state modeled via `storageMapUint` keyed by e3Id
  - `claimed` nested mapping modeled as `storageMap2` (Uint256 → Address → Uint256)
  - BPS math (work allocations, honest node counts, per-node amounts) — trust boundary,
    modeled as oracle (simplified amounts stored directly)
  - ERC20 transfers — not modeled (trust boundary)
  - `interfold.getRequester(e3Id)` external call — trust boundary
  - `interfold.getFailureReason(e3Id)` external call — trust boundary
  - Honest node array iteration — trust boundary
  - Treasury pull-payment ledgers — trust boundary
  - Rounding dust and split logic — trust boundary

  Proof objectives (see PROOF_OBJECTIVES.md):
  - E3RM-P1: calculateRefund reverts when already calculated (idempotency)
  - E3RM-P2: claimRequesterRefund reverts when already claimed (replay protection)
  - E3RM-P3: escrowSlashedFunds reverts without onlyInterfold
  - E3RM-P4: calculateRefund reverts without onlyInterfold
  - E3RM-P5: On success, claimRequesterRefund sets claimed[e3Id][sender] = true
-/
import Contracts.Common

namespace Contracts.E3RefundManager

open Verity hiding pure bind
open Verity.EVM.Uint256

verity_contract E3RefundManager where
  storage
    -- Address slots
    interfold : Address := slot 0
    owner : Address := slot 1

    -- Per-E3 distribution state (storageMapUint: Uint256 → Uint256)
    calculated : Uint256 → Uint256 := slot 2
    requesterAmount : Uint256 → Uint256 := slot 3
    honestNodeAmount : Uint256 → Uint256 := slot 4
    perNodeAmount : Uint256 → Uint256 := slot 5
    originalPayment : Uint256 → Uint256 := slot 6
    honestNodeCount : Uint256 → Uint256 := slot 7

    -- Claim tracking: nested mapping e3Id → address → claimed (0/1)
    claimed : Uint256 → Address → Uint256 := slot 8

    -- Per-E3 claim count
    claimCount : Uint256 → Uint256 := slot 9

    -- Pending slashed funds per E3
    pendingSlashedFunds : Uint256 → Uint256 := slot 10

  -- Guard: restrict function to Interfold contract only
  function onlyInterfold : Unit := do
    let sender ← msgSender
    let ifold ← getStorage interfold
    require (sender == ifold) "caller is not Interfold"

  -- Guard: restrict function to contract owner only
  function onlyOwner : Unit := do
    let sender ← msgSender
    let own ← getStorage owner
    require (sender == own) "caller is not owner"

  -- calculateRefund(e3Id, originalPayment)
  -- Only Interfold. Reverts if already calculated.
  -- Stores distribution amounts (BPS math is trust boundary — simplified).
  function calculateRefund (e3Id : Uint256) (originalPayment : Uint256) : Unit := do
    onlyInterfold
    let calc ← getMapping calculated e3Id
    require (calc == 0) "Already calculated"
    require (originalPayment > 0) "No payment"
    -- Store distribution amounts (simplified — trust BPS math oracle)
    setMapping calculated e3Id 1
    setMapping originalPayment e3Id originalPayment
    setMapping requesterAmount e3Id originalPayment
    setMapping perNodeAmount e3Id 1
    emitEvent "RefundDistributionCalculated" [e3Id] []

  -- claimRequesterRefund(e3Id)
  -- Only callable by the E3 requester. Reverts if not calculated or already claimed.
  -- On success, sets claimed[e3Id][sender] = 1.
  function claimRequesterRefund (e3Id : Uint256) : Unit := do
    let calc ← getMapping calculated e3Id
    require (calc == 1) "Refund not calculated"
    let sender ← msgSender
    let alreadyClaimed ← getMapping2 claimed e3Id sender
    require (alreadyClaimed == 0) "Already claimed"
    -- Increment claim count
    let cnt ← getMapping claimCount e3Id
    let newCnt ← requireSomeUint (safeAdd cnt 1) "count overflow"
    setMapping claimCount e3Id newCnt
    -- Mark as claimed
    setMapping2 claimed e3Id sender 1
    -- ERC20 transfer: trust boundary (not modeled)
    let amt ← getMapping requesterAmount e3Id
    require (amt > 0) "No refund available"
    emitEvent "RefundClaimed" [e3Id, amt] [addressToWord sender]

  -- claimHonestNodeReward(e3Id)
  -- Only callable by honest nodes. Reverts if not calculated or already claimed.
  -- On success, sets claimed[e3Id][sender] = 1.
  -- Honest node membership check is a trust boundary (requires array iteration).
  function claimHonestNodeReward (e3Id : Uint256) : Unit := do
    let calc ← getMapping calculated e3Id
    require (calc == 1) "Refund not calculated"
    let sender ← msgSender
    let alreadyClaimed ← getMapping2 claimed e3Id sender
    require (alreadyClaimed == 0) "Already claimed"
    -- Increment claim count
    let cnt ← getMapping claimCount e3Id
    let newCnt ← requireSomeUint (safeAdd cnt 1) "count overflow"
    setMapping claimCount e3Id newCnt
    -- Mark as claimed
    setMapping2 claimed e3Id sender 1
    -- ERC20 transfer: trust boundary (not modeled)
    let amt ← getMapping perNodeAmount e3Id
    require (amt > 0) "No refund available"
    emitEvent "RefundClaimed" [e3Id, amt] [addressToWord sender]

  -- escrowSlashedFunds(e3Id, amount)
  -- Only Interfold. Increments pending slashed funds.
  -- Post-calculation routing to honest nodes / requester is a trust boundary.
  function escrowSlashedFunds (e3Id : Uint256) (amount : Uint256) : Unit := do
    onlyInterfold
    require (amount > 0) "Zero amount"
    let pending ← getMapping pendingSlashedFunds e3Id
    let newPending ← requireSomeUint (safeAdd pending amount) "overflow"
    setMapping pendingSlashedFunds e3Id newPending
    emitEvent "SlashedFundsEscrowed" [e3Id, amount] []

  -- distributeSlashedFundsOnSuccess(e3Id)
  -- Only Interfold. Distributes pending slashed funds (BPS math and node splits
  -- are trust boundaries).
  function distributeSlashedFundsOnSuccess (e3Id : Uint256) : Unit := do
    onlyInterfold
    let escrowed ← getMapping pendingSlashedFunds e3Id
    if escrowed == 0 then
      pure ()
    else
      setMapping pendingSlashedFunds e3Id 0
      emitEvent "SlashedFundsDistributedOnSuccess" [e3Id, escrowed] []

  -- setWorkAllocation
  -- Only owner. Sets BPS allocation values (trust boundary).
  function setWorkAllocation : Unit := do
    onlyOwner
    -- BPS allocation values are an oracle — we only model the access control
    emitEvent "WorkAllocationUpdated" [] []

  -- withdrawOrphanedSlashedFunds(e3Id)
  -- Only owner. Drains pending slashed funds for an E3 in terminal state.
  -- E3 terminal state check is an oracle (external call).
  function withdrawOrphanedSlashedFunds (e3Id : Uint256) : Unit := do
    onlyOwner
    let pending ← getMapping pendingSlashedFunds e3Id
    require (pending > 0) "No orphaned funds"
    setMapping pendingSlashedFunds e3Id 0
    emitEvent "OrphanedSlashedFundsWithdrawn" [e3Id, pending] []

end Contracts.E3RefundManager
