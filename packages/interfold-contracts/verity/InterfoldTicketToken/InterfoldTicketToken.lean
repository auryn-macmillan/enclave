/-
  InterfoldTicketToken — Formally Verified Implementation

  Translation of `packages/interfold-contracts/contracts/token/InterfoldTicketToken.sol`
  into the Verity EDSL. Models the core peg-invariant, access control (onlyRegistry),
  transfer blocking, and registry timelock change flow.

  This is a non-transferable, non-delegatable ERC20Votes wrapper.

  Trust boundaries:
  - Underlying ERC20 transfers (SafeERC20) are modeled as direct balance deltas
  - EIP-6372 clock (timestamp) is trusted from EVM context
  - Voting/delegation mechanics are not modeled (separate trust surface)
-/
import Verity.Core
import Verity.Specs.Common

open Verity

/-! ## Storage slot definitions -/

def underlyingBalSlot : StorageSlot Uint256 := ⟨0⟩       -- balance of underlying held by contract
def totalSupplySlot : StorageSlot Uint256 := ⟨1⟩          -- total ITK supply
def balancesSlot : StorageSlot (Address → Uint256) := ⟨2⟩ -- ITK balances
def registrySlot : StorageSlot Address := ⟨3⟩             -- authorized registry address
def registryLockedSlot : StorageSlot Bool := ⟨4⟩          -- whether registry is locked
def pendingRegistrySlot : StorageSlot Address := ⟨5⟩     -- pending registry change
def pendingRegistryTimeSlot : StorageSlot Uint256 := ⟨6⟩ -- activation timestamp
def payableBalanceSlot : StorageSlot Uint256 := ⟨7⟩       -- accumulated underlying from burns
def ownerSlot : StorageSlot Address := ⟨8⟩               -- contract owner

/-! ## Constants -/

def REGISTRY_CHANGE_DELAY : Uint256 := 86400  -- 1 day in seconds

/-! ## Helpers -/

/-- Guard: caller must be the owner. -/
def onlyOwner : Contract Unit := do
  let sender ← msgSender
  let owner ← getStorageAddr ownerSlot
  require (sender == owner) "not owner"

/-- Guard: caller must be the registry. -/
def onlyRegistry : Contract Unit := do
  let sender ← msgSender
  let reg ← getStorageAddr registrySlot
  require (sender == reg) "not registry"

/-! ## Core token functions -/

/--
  Internal mint: increase `to`'s ITK balance and totalSupply.
  Also increases the underlying balance to maintain the 1:1 peg.
-/
def doMint (to : Address) (amount : Uint256) : Contract Unit := do
  let currentBal ← getMapping balancesSlot to
  let newBal ← requireSomeUint (safeAdd currentBal amount) "balance overflow"
  let currentSupply ← getStorage totalSupplySlot
  let newSupply ← requireSomeUint (safeAdd currentSupply amount) "supply overflow"
  let currentUnderlying ← getStorage underlyingBalSlot
  let newUnderlying ← requireSomeUint (safeAdd currentUnderlying amount) "underlying overflow"
  setMapping balancesSlot to newBal
  setStorage totalSupplySlot newSupply
  setStorage underlyingBalSlot newUnderlying

/--
  Internal burn: decrease `from`'s ITK balance and totalSupply.
  Does NOT decrease underlying (burning tickets leaves underlying in the contract).
-/
def doBurn (from : Address) (amount : Uint256) : Contract Unit := do
  let currentBal ← getMapping balancesSlot from
  require (currentBal >= amount) "insufficient balance"
  let newBal ← requireSomeUint (safeSub currentBal amount) "balance underflow"
  let currentSupply ← getStorage totalSupplySlot
  let newSupply ← requireSomeUint (safeSub currentSupply amount) "supply underflow"
  setMapping balancesSlot from newBal
  setStorage totalSupplySlot newSupply

/--
  Internal withdraw: burn ITK and decrease underlying balance.
  Maintains the 1:1 peg on the withdrawal side.
-/
def doWithdraw (from : Address) (amount : Uint256) : Contract Unit := do
  let currentBal ← getMapping balancesSlot from
  require (currentBal >= amount) "insufficient balance"
  let newBal ← requireSomeUint (safeSub currentBal amount) "balance underflow"
  let currentSupply ← getStorage totalSupplySlot
  let newSupply ← requireSomeUint (safeSub currentSupply amount) "supply underflow"
  let currentUnderlying ← getStorage underlyingBalSlot
  let newUnderlying ← requireSomeUint (safeSub currentUnderlying amount) "underlying underflow"
  setMapping balancesSlot from newBal
  setStorage totalSupplySlot newSupply
  setStorage underlyingBalSlot newUnderlying

/-! ## Public entrypoints -/

/--
  `depositFor(operator, amount)` — mints ITK to operator.
  Only callable by the registry. Auto-self-delegates (not modeled).
  Fee-on-transfer safe: mints based on actual received (modeled as direct amount for simplicity;
  in production the delta between before/after underlying balance is used).
-/
def depositFor (operator : Address) (amount : Uint256) : Contract Unit := do
  onlyRegistry
  require (operator != 0) "zero address"
  require (amount != 0) "zero amount"
  doMint operator amount
  emitEvent "Deposit" [amount] [addressToWord operator]

/--
  `withdrawTo(receiver, amount)` — burns ITK from registry and returns underlying.
  Only callable by the registry.
-/
def withdrawTo (receiver : Address) (amount : Uint256) : Contract Unit := do
  onlyRegistry
  require (receiver != 0) "zero address"
  require (amount != 0) "zero amount"
  let sender ← msgSender
  doWithdraw sender amount
  emitEvent "Withdrawal" [amount] [addressToWord receiver]

/--
  `burnTickets(operator, amount)` — burns ITK from operator without returning underlying.
  Only callable by the registry. Increments payableBalance.
-/
def burnTickets (operator : Address) (amount : Uint256) : Contract Unit := do
  onlyRegistry
  require (operator != 0) "zero address"
  require (amount != 0) "zero amount"
  let currentPayable ← getStorage payableBalanceSlot
  let newPayable ← requireSomeUint (safeAdd currentPayable amount) "payable overflow"
  setStorage payableBalanceSlot newPayable
  doBurn operator amount
  emitEvent "TicketsBurned" [amount] [addressToWord operator]

/--
  `payout(to, amount)` — transfers underlying from payableBalance.
  Only callable by the registry. Reverts if amount exceeds payableBalance.
-/
def payoutOp (to : Address) (amount : Uint256) : Contract Unit := do
  onlyRegistry
  require (to != 0) "zero address"
  let currentPayable ← getStorage payableBalanceSlot
  require (amount <= currentPayable) "exceeds payable balance"
  let newPayable ← requireSomeUint (safeSub currentPayable amount) "payable underflow"
  let currentUnderlying ← getStorage underlyingBalSlot
  let newUnderlying ← requireSomeUint (safeSub currentUnderlying amount) "underlying underflow"
  setStorage payableBalanceSlot newPayable
  setStorage underlyingBalSlot newUnderlying
  emitEvent "Payout" [amount] [addressToWord to]

/--
  Transfer hook: reverts if both from and to are non-zero (blocks all transfers).
  Minting (from == 0) and burning (to == 0) are allowed.
-/
def doTransfer (from : Address) (to : Address) (amount : Uint256) : Contract Unit := do
  if from != 0 && to != 0 then
    require (false) "transfer not allowed"
  else do
    -- This is a mint (from=0) or burn (to=0), handled by doMint/doBurn directly
    pure ()

/-! ## Registry management -/

/--
  `setRegistry(newRegistry)` — instant registry update (only before lock).
-/
def setRegistry (newRegistry : Address) : Contract Unit := do
  onlyOwner
  let locked ← getStorage registryLockedSlot
  require (!locked) "registry already locked"
  require (newRegistry != 0) "zero address"
  setStorageAddr registrySlot newRegistry
  emitEvent "RegistryChanged" [0] [addressToWord newRegistry]

/--
  `lockRegistry()` — one-way switch forcing future changes through delayed flow.
-/
def lockRegistry : Contract Unit := do
  onlyOwner
  let locked ← getStorage registryLockedSlot
  require (!locked) "registry lock already set"
  setStorage registryLockedSlot true
  emitEvent "RegistryLocked" [] []

/--
  `requestRegistryChange(newRegistry)` — stage a timelocked registry swap.
-/
def requestRegistryChange (newRegistry : Address) : Contract Unit := do
  onlyOwner
  let locked ← getStorage registryLockedSlot
  require locked "registry not locked"
  require (newRegistry != 0) "zero address"
  let timestamp ← getBlockTimestamp
  let activatesAt ← requireSomeUint (safeAdd timestamp REGISTRY_CHANGE_DELAY) "timestamp overflow"
  setStorageAddr pendingRegistrySlot newRegistry
  setStorage pendingRegistryTimeSlot activatesAt
  emitEvent "RegistryChangeRequested" [activatesAt] [addressToWord newRegistry]

/--
  `activateRegistryChange()` — apply pending registry swap after timelock.
-/
def activateRegistryChange : Contract Unit := do
  onlyOwner
  let pending ← getStorageAddr pendingRegistrySlot
  require (pending != 0) "no pending registry"
  let activatesAt ← getStorage pendingRegistryTimeSlot
  let now ← getBlockTimestamp
  require (now >= activatesAt) "registry change not ready"
  setStorageAddr registrySlot pending
  setStorageAddr pendingRegistrySlot 0
  setStorage pendingRegistryTimeSlot 0
  emitEvent "RegistryChanged" [0] [addressToWord pending]

/--
  `cancelRegistryChange()` — discard pending registry change.
-/
def cancelRegistryChange : Contract Unit := do
  onlyOwner
  let pending ← getStorageAddr pendingRegistrySlot
  require (pending != 0) "no pending registry"
  setStorageAddr pendingRegistrySlot 0
  setStorage pendingRegistryTimeSlot 0
  emitEvent "RegistryChangeCancelled" [] [addressToWord pending]

/-! ## Approve / permit / delegate are disabled -/

/--
  `approve` always reverts — ticket tokens are non-transferable.
-/
def approve : Contract Unit := do
  require (false) "transfer not allowed"

/--
  `permit` always reverts — allowances are disabled.
-/
def permit : Contract Unit := do
  require (false) "permit disabled"

/--
  `delegateOp(delegatee)` — only self-delegation allowed.
-/
def delegateOp (delegatee : Address) : Contract Unit := do
  let sender ← msgSender
  require (delegatee == sender) "delegation locked"

/-! ## Initialization -/

/--
  Initialize the ticket token with an underlying, registry, and owner.
-/
def initTicketToken (registry_ : Address) (initialOwner : Address) : Contract Unit := do
  require (registry_ != 0) "zero address registry"
  require (initialOwner != 0) "zero address owner"
  setStorageAddr ownerSlot initialOwner
  setStorageAddr registrySlot registry_
  emitEvent "RegistryChanged" [0] [addressToWord registry_]
