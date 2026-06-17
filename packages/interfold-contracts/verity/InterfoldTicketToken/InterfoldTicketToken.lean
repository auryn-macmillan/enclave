/-
  InterfoldTicketToken — Verity Formal Verification

  Faithful translation of `contracts/token/InterfoldTicketToken.sol` using `verity_contract`.

  Modeling decisions:
  - `onlyRegistry` guard: checks msg.sender == registry (address storage slot)
  - `onlyOwner` guard: checks msg.sender == owner (address storage slot)
  - Registry lifecycle (setRegistry, lockRegistry, requestRegistryChange,
    activateRegistryChange, cancelRegistryChange) modeled faithfully with timelock
  - `_update` blocks all transfers between non-zero addresses
  - `approve`/`permit` always revert
  - `delegate` only allows self-delegation (reverts otherwise)
  - Fee-on-transfer delta measurement is a trust boundary — modeled as exact amount
  - ERC20Votes delegation checkpoint logic is NOT modeled (trust boundary)
  - ERC20Permit beyond the `permit` revert is NOT modeled (trust boundary)
  - ReentrancyGuard not modeled (single-contract scope)
  - Uint256 used for boolean storage (1 = true, 0 = false)

  Proof objectives (see PROOF_OBJECTIVES.md):
  - ITK-P1: Registry-guarded functions revert when msg.sender ≠ registry
  - ITK-P2: burnTickets accounting (payableBalance increase, operator balance decrease,
            totalSupply decrease)
  - ITK-P3: payout reverts when amount > payableBalance
  - ITK-P4: payout accounting (payableBalance and underlyingBal decrease)
  - ITK-P5: _update reverts when from ≠ 0 and to ≠ 0 (non-transferable)
  - ITK-P6: approve always reverts
  - ITK-P7: permit always reverts
  - ITK-P8: delegate reverts when delegatee ≠ msg.sender
  - ITK-P9: activateRegistryChange reverts before timelock
  - ITK-P10: lockRegistry sets registryLocked from false → true; reverts when already true
  - ITK-P11: setRegistry reverts when registryLocked == true
  - ITK-P12: requestRegistryChange reverts when registryLocked == false
  - ITK-PEG: Peg invariant (totalSupply == underlyingBal + payableBalance) preserved
    by each operation
-/
import Contracts.Common

namespace Contracts.InterfoldTicketToken

open Verity hiding pure bind
open Verity.EVM.Uint256

/-! ## Registry change delay constant -/

def REGISTRY_CHANGE_DELAY : Uint256 := 86400  -- 1 day

/-! ## Contract -/

verity_contract InterfoldTicketToken where
  storage
    -- ERC20 state
    balances : Address -> Uint256 := slot 0
    totalSupply : Uint256 := slot 1
    -- Underlying token balance (modeled directly; Solidity uses ERC20 external calls)
    underlyingBal : Uint256 := slot 2
    -- Registry guard
    registry : Address := slot 3
    -- Ownable pattern
    owner : Address := slot 4
    -- Registry lock: 1 = true, 0 = false (Uint256 storage, matching InterfoldToken pattern)
    registryLocked : Uint256 := slot 5
    -- Payable balance (slashed funds available for payout)
    payableBalance : Uint256 := slot 6
    -- Pending registry change
    pendingRegistry : Address := slot 7
    pendingRegistryActivationTime : Uint256 := slot 8

  -- Guard: onlyRegistry — reverts if msg.sender ≠ registry
  function onlyRegistry : Unit := do
    let sender ← msgSender
    let reg ← getStorageAddr registry
    require (sender == reg) "not registry"

  -- Guard: onlyOwner — reverts if msg.sender ≠ owner
  function onlyOwner : Unit := do
    let sender ← msgSender
    let own ← getStorageAddr owner
    require (sender == own) "not owner"

  -- depositFor(operator, amount) — Mint ITK to operator from underlying deposit.
  -- Only callable by the registry. Fee-on-transfer delta is a trust boundary;
  -- modeled as exact amount.
  function depositFor (operator : Address) (amount : Uint256) : Unit := do
    onlyRegistry
    require (operator != 0) "zero address"
    require (amount != 0) "zero amount"
    let currentBal ← getMapping balances operator
    let newBal ← requireSomeUint (safeAdd currentBal amount) "balance overflow"
    let currentSupply ← getStorage totalSupply
    let newSupply ← requireSomeUint (safeAdd currentSupply amount) "supply overflow"
    let currentUnder ← getStorage underlyingBal
    let newUnder ← requireSomeUint (safeAdd currentUnder amount) "underlying overflow"
    setMapping balances operator newBal
    setStorage totalSupply newSupply
    setStorage underlyingBal newUnder
    emitEvent "Deposit" [amount] [addressToWord operator]

  -- depositFrom(from, to, amount) — Transfer underlying from 'from' and mint ITK to 'to'.
  -- Only callable by the registry. Same trust boundary as depositFor.
  function depositFrom (from : Address) (to : Address) (amount : Uint256) : Unit := do
    onlyRegistry
    require (from != 0) "zero from"
    require (to != 0) "zero to"
    require (amount != 0) "zero amount"
    let currentBal ← getMapping balances to
    let newBal ← requireSomeUint (safeAdd currentBal amount) "balance overflow"
    let currentSupply ← getStorage totalSupply
    let newSupply ← requireSomeUint (safeAdd currentSupply amount) "supply overflow"
    let currentUnder ← getStorage underlyingBal
    let newUnder ← requireSomeUint (safeAdd currentUnder amount) "underlying overflow"
    setMapping balances to newBal
    setStorage totalSupply newSupply
    setStorage underlyingBal newUnder
    emitEvent "DepositFrom" [amount] [addressToWord from, addressToWord to]

  -- withdrawTo(receiver, amount) — Burn ITK from caller (the registry) and transfer
  -- underlying tokens. Only callable by the registry.
  function withdrawTo (receiver : Address) (amount : Uint256) : Unit := do
    onlyRegistry
    let sender ← msgSender
    require (amount != 0) "zero amount"
    let currentBal ← getMapping balances sender
    require (currentBal >= amount) "insufficient balance"
    let newBal ← requireSomeUint (safeSub currentBal amount) "balance underflow"
    let currentSupply ← getStorage totalSupply
    let newSupply ← requireSomeUint (safeSub currentSupply amount) "supply underflow"
    let currentUnder ← getStorage underlyingBal
    let newUnder ← requireSomeUint (safeSub currentUnder amount) "underlying underflow"
    setMapping balances sender newBal
    setStorage totalSupply newSupply
    setStorage underlyingBal newUnder
    emitEvent "Withdrawal" [amount] [addressToWord receiver]

  -- burnTickets(operator, amount) — Burn ITK without transferring underlying (slash).
  -- Increases payableBalance. Only callable by the registry.
  -- Key: underlyingBal UNCHANGED, totalSupply decreases, payableBalance increases.
  function burnTickets (operator : Address) (amount : Uint256) : Unit := do
    onlyRegistry
    require (amount != 0) "zero amount"
    let currentPay ← getStorage payableBalance
    let newPay ← requireSomeUint (safeAdd currentPay amount) "payable overflow"
    let currentBal ← getMapping balances operator
    require (currentBal >= amount) "insufficient balance"
    let newBal ← requireSomeUint (safeSub currentBal amount) "balance underflow"
    let currentSupply ← getStorage totalSupply
    let newSupply ← requireSomeUint (safeSub currentSupply amount) "supply underflow"
    setStorage payableBalance newPay
    setMapping balances operator newBal
    setStorage totalSupply newSupply
    emitEvent "TicketsBurned" [amount] [addressToWord operator]

  -- payout(to, amount) — Transfer underlying without burning ITK.
  -- Requires amount ≤ payableBalance. Only callable by the registry.
  function payout (to : Address) (amount : Uint256) : Unit := do
    onlyRegistry
    require (amount != 0) "zero amount"
    let currentPay ← getStorage payableBalance
    require (amount <= currentPay) "exceeds payable balance"
    let newPay ← requireSomeUint (safeSub currentPay amount) "payable underflow"
    let currentUnder ← getStorage underlyingBal
    let newUnder ← requireSomeUint (safeSub currentUnder amount) "underlying underflow"
    setStorage payableBalance newPay
    setStorage underlyingBal newUnder
    emitEvent "Payout" [amount] [addressToWord to]

  -- doUpdate(from, to, value) — Internal transfer hook.
  -- Blocks ALL transfers between non-zero addresses (non-transferable).
  -- Mints (from=0) and burns (to=0) are allowed.
  function doUpdate (from : Address) (to : Address) (value : Uint256) : Unit := do
    -- Transfer restriction: block all non-zero ↔ non-zero transfers
    if from != 0 && to != 0 then
      require (false) "transfer not allowed"
    else
      pure ()
    -- Balance updates
    if from == 0 then
      pure ()
    else
      let fromBal ← getMapping balances from
      require (fromBal >= value) "insufficient balance"
      let newFrom ← requireSomeUint (safeSub fromBal value) "balance underflow"
      setMapping balances from newFrom
    if to == 0 then
      pure ()
    else
      let toBal ← getMapping balances to
      let newTo ← requireSomeUint (safeAdd toBal value) "balance overflow"
      setMapping balances to newTo
    -- totalSupply updates
    if from == 0 then
      -- Mint: increase totalSupply
      let currentSupply ← getStorage totalSupply
      let newSupply ← requireSomeUint (safeAdd currentSupply value) "supply overflow"
      setStorage totalSupply newSupply
    else if to == 0 then
      -- Burn: decrease totalSupply
      let currentSupply ← getStorage totalSupply
      let newSupply ← requireSomeUint (safeSub currentSupply value) "supply underflow"
      setStorage totalSupply newSupply
    else
      pure ()

  -- transfer(to, amount) — Public transfer. Delegates to doUpdate with msg.sender as from.
  -- Will revert via doUpdate if from ≠ 0 and to ≠ 0 (i.e., all non-mint/non-burn transfers).
  function transfer (to : Address) (amount : Uint256) : Unit := do
    let sender ← msgSender
    doUpdate sender to amount
    emitEvent "Transfer" [amount] [addressToWord sender, addressToWord to]

  -- approve: always revert (allowances and transfers are disabled on this token)
  function approve (spender : Address) (amount : Uint256) : Unit := do
    require (false) "transfer not allowed"

  -- permit: always revert (ERC-2612 is disabled)
  function permit (_owner : Address) (_spender : Address) (_value : Uint256)
    (_deadline : Uint256) (_v : Uint256) (_r : Uint256) (_s : Uint256) : Unit := do
    require (false) "permit disabled"

  -- delegate(delegatee): only self-delegation is allowed.
  -- Reverts if delegatee ≠ msg.sender.
  function delegate (delegatee : Address) : Unit := do
    let sender ← msgSender
    require (delegatee == sender) "delegation locked"

  -- delegateBySig: always revert (delegation-by-signature is disabled)
  function delegateBySig (_delegatee : Address) (_nonce : Uint256)
    (_expiry : Uint256) (_v : Uint256) (_r : Uint256) (_s : Uint256) : Unit := do
    require (false) "delegation locked"

  -- setRegistry(newRegistry): onlyOwner, revert if registryLocked.
  -- Allows instant registry update before the lock is set.
  function setRegistry (newRegistry : Address) : Unit := do
    onlyOwner
    let locked ← getStorage registryLocked
    require (locked == 0) "registry already locked"
    require (newRegistry != 0) "zero address"
    let old ← getStorageAddr registry
    setStorageAddr registry newRegistry
    emitEvent "RegistryChanged" [] [addressToWord old, addressToWord newRegistry]

  -- lockRegistry(): onlyOwner, one-way switch false → true. Reverts if already true.
  function lockRegistry : Unit := do
    onlyOwner
    let locked ← getStorage registryLocked
    require (locked == 0) "registry lock already set"
    setStorage registryLocked 1
    emitEvent "RegistryLocked" [] []

  -- requestRegistryChange(newRegistry): onlyOwner, revert if not locked.
  -- Stages a pending registry change with a timelock.
  function requestRegistryChange (newRegistry : Address) : Unit := do
    onlyOwner
    let locked ← getStorage registryLocked
    require (locked == 1) "registry not locked"
    require (newRegistry != 0) "zero address"
    let now ← getBlockTimestamp
    let activatesAt ← requireSomeUint (safeAdd now REGISTRY_CHANGE_DELAY) "time overflow"
    setStorageAddr pendingRegistry newRegistry
    setStorage pendingRegistryActivationTime activatesAt
    emitEvent "RegistryChangeRequested" [activatesAt] [addressToWord newRegistry]

  -- activateRegistryChange(): onlyOwner, reverts if no pending or timelock not expired.
  -- Applies the pending registry change.
  function activateRegistryChange : Unit := do
    onlyOwner
    let pending ← getStorageAddr pendingRegistry
    require (pending != 0) "no pending registry"
    let activatesAt ← getStorage pendingRegistryActivationTime
    let now ← getBlockTimestamp
    require (now >= activatesAt) "registry change not ready"
    let old ← getStorageAddr registry
    setStorageAddr registry pending
    setStorageAddr pendingRegistry 0
    setStorage pendingRegistryActivationTime 0
    emitEvent "RegistryChanged" [] [addressToWord old, addressToWord pending]

  -- cancelRegistryChange(): onlyOwner, reverts if no pending.
  -- Discards the pending registry change.
  function cancelRegistryChange : Unit := do
    onlyOwner
    let pending ← getStorageAddr pendingRegistry
    require (pending != 0) "no pending registry"
    setStorageAddr pendingRegistry 0
    setStorage pendingRegistryActivationTime 0
    emitEvent "RegistryChangeCancelled" [] [addressToWord pending]

end Contracts.InterfoldTicketToken
