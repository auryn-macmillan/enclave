/-
  InterfoldTicketToken — Verity Formal Verification

  Faithful translation of `contracts/token/InterfoldTicketToken.sol` using `verity_contract`.

  Storage layout note: OpenZeppelin AccessControl uses
  `mapping(bytes32 => mapping(address => uint256))` for role membership.
  Verity's getMapping2 only supports Address→Address keys, so we model each
  role as a separate `Address → Uint256` mapping.

  Trust boundaries (NOT modeled):
  - Fee-on-transfer delta measurement — modeled as exact amount
  - ERC20Votes delegation checkpoint logic
  - ERC20Permit beyond the `permit` revert
  - ReentrancyGuard (single-contract scope)
-/
import Contracts.Common

namespace InterfoldContracts

open Verity hiding pure bind
open Verity.EVM.Uint256
open Verity.Stdlib.Math

def InterfoldContracts.InterfoldTicketToken.REGISTRY_CHANGE_DELAY : Uint256 := 86400  -- 1 day

verity_contract InterfoldTicketToken where
  storage
    balances : Address → Uint256 := slot 0
    totalSupply : Uint256 := slot 1
    underlyingBal : Uint256 := slot 2
    registry : Address := slot 3
    owner : Address := slot 4
    registryLocked : Uint256 := slot 5
    payableBalance : Uint256 := slot 6
    pendingRegistry : Address := slot 7
    pendingRegistryActivationTime : Uint256 := slot 8

  function depositFor (operator : Address, amount : Uint256) : Unit := do
    let sender ← msgSender
    let reg ← getStorageAddr registry
    require (sender == reg) "not registry"
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

  function depositFrom (fromAddr : Address, toAddr : Address, amount : Uint256) : Unit := do
    let sender ← msgSender
    let reg ← getStorageAddr registry
    require (sender == reg) "not registry"
    require (fromAddr != 0) "zero from"
    require (toAddr != 0) "zero to"
    require (amount != 0) "zero amount"
    let currentBal ← getMapping balances toAddr
    let newBal ← requireSomeUint (safeAdd currentBal amount) "balance overflow"
    let currentSupply ← getStorage totalSupply
    let newSupply ← requireSomeUint (safeAdd currentSupply amount) "supply overflow"
    let currentUnder ← getStorage underlyingBal
    let newUnder ← requireSomeUint (safeAdd currentUnder amount) "underlying overflow"
    setMapping balances toAddr newBal
    setStorage totalSupply newSupply
    setStorage underlyingBal newUnder

  function withdrawTo (receiver : Address, amount : Uint256) : Unit := do
    let sender ← msgSender
    let reg ← getStorageAddr registry
    require (sender == reg) "not registry"
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

  function burnTickets (operator : Address, amount : Uint256) : Unit := do
    let sender ← msgSender
    let reg ← getStorageAddr registry
    require (sender == reg) "not registry"
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

  function payout (toAddr : Address, amount : Uint256) : Unit := do
    let sender ← msgSender
    let reg ← getStorageAddr registry
    require (sender == reg) "not registry"
    require (amount != 0) "zero amount"
    let currentPay ← getStorage payableBalance
    require (amount <= currentPay) "exceeds payable balance"
    let newPay ← requireSomeUint (safeSub currentPay amount) "payable underflow"
    let currentUnder ← getStorage underlyingBal
    let newUnder ← requireSomeUint (safeSub currentUnder amount) "underlying underflow"
    setStorage payableBalance newPay
    setStorage underlyingBal newUnder

  function approve (spender : Address, amount : Uint256) : Unit := do
    require (false) "transfer not allowed"

  function delegate (delegatee : Address) : Unit := do
    let sender ← msgSender
    require (delegatee == sender) "delegation locked"

  function setRegistry (newRegistry : Address) : Unit := do
    let sender ← msgSender
    let own ← getStorageAddr owner
    require (sender == own) "not owner"
    let locked ← getStorage registryLocked
    require (locked == 0) "registry already locked"
    require (newRegistry != 0) "zero address"
    setStorageAddr registry newRegistry

  function lockRegistry () : Unit := do
    let sender ← msgSender
    let own ← getStorageAddr owner
    require (sender == own) "not owner"
    let locked ← getStorage registryLocked
    require (locked == 0) "registry lock already set"
    setStorage registryLocked 1

  function requestRegistryChange (newRegistry : Address) : Unit := do
    let sender ← msgSender
    let own ← getStorageAddr owner
    require (sender == own) "not owner"
    let locked ← getStorage registryLocked
    require (locked == 1) "registry not locked"
    require (newRegistry != 0) "zero address"
    let now ← blockTimestamp
    let activatesAt ← requireSomeUint (safeAdd now 86400) "time overflow"
    setStorageAddr pendingRegistry newRegistry
    setStorage pendingRegistryActivationTime activatesAt

  function activateRegistryChange () : Unit := do
    let sender ← msgSender
    let own ← getStorageAddr owner
    require (sender == own) "not owner"
    let pending ← getStorageAddr pendingRegistry
    require (pending != 0) "no pending registry"
    let activatesAt ← getStorage pendingRegistryActivationTime
    let now ← blockTimestamp
    require (now >= activatesAt) "registry change not ready"
    setStorageAddr registry pending
    setStorageAddr pendingRegistry 0
    setStorage pendingRegistryActivationTime 0

  function cancelRegistryChange () : Unit := do
    let sender ← msgSender
    let own ← getStorageAddr owner
    require (sender == own) "not owner"
    let pending ← getStorageAddr pendingRegistry
    require (pending != 0) "no pending registry"
    setStorageAddr pendingRegistry 0
    setStorage pendingRegistryActivationTime 0

namespace InterfoldTicketToken

def onlyRegistry : Contract Unit := do
  let sender ← msgSender
  let reg ← getStorageAddr registry
  require (sender == reg) "not registry"

def onlyOwner : Contract Unit := do
  let sender ← msgSender
  let own ← getStorageAddr owner
  require (sender == own) "not owner"

end InterfoldTicketToken

end InterfoldContracts
