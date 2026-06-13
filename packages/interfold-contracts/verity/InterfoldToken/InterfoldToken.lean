/-
  InterfoldToken — Formally Verified Implementation

  Translation of `packages/interfold-contracts/contracts/token/InterfoldToken.sol`
  into the Verity EDSL. This models the core mint-cap, transfer-restriction, and
  whitelist logic. AccessControl role management is modeled as a simplified owner
  + minter + whitelist-manager pattern to keep the proof surface focused on the
  critical safety properties.

  Trust boundaries:
  - ERC20 base (_mint, _burn) is modeled directly (no external OZ dependency)
  - EIP-6372 clock (timestamp mode) is trusted from the EVM context
  - Permit and voting extensions are not modeled (separate trust surface)
-/
import Verity.Core
import Verity.Specs.Common

open Verity

/-! ## Storage slot definitions -/

def balancesSlot : StorageSlot (Address → Uint256) := ⟨0⟩
def totalSupplySlot : StorageSlot Uint256 := ⟨1⟩
def totalMintedSlot : StorageSlot Uint256 := ⟨2⟩
def transfersRestrictedSlot : StorageSlot Bool := ⟨3⟩
def transferWhitelistedSlot : StorageSlot (Address → Bool) := ⟨4⟩
def ownerSlot : StorageSlot Address := ⟨5⟩
def minterSlot : StorageSlot Address := ⟨6⟩
def whitelistManagerSlot : StorageSlot Address := ⟨7⟩

/-! ## Constants -/

def MAX_SUPPLY : Uint256 := 1200000000000000000000000000  -- 1.2B * 1e18

/-! ## Helpers -/

/-- Guard: caller must be the owner. Reverts with "not owner" if not. -/
def onlyOwner : Contract Unit := do
  let sender ← msgSender
  let owner ← getStorageAddr ownerSlot
  require (sender == owner) "not owner"

/-- Guard: caller must be the minter. Reverts with "not minter" if not. -/
def onlyMinter : Contract Unit := do
  let sender ← msgSender
  let minter ← getStorageAddr minterSlot
  require (sender == minter) "not minter"

/-- Guard: caller must be the whitelist manager. Reverts with "not whitelist manager" if not. -/
def onlyWhitelistManager : Contract Unit := do
  let sender ← msgSender
  let manager ← getStorageAddr whitelistManagerSlot
  require (sender == manager) "not whitelist manager"

/-! ## Core token functions -/

/--
  Mint new tokens to `to`. This is the internal _mint equivalent.
  Increments `to`'s balance and `totalSupply`.
-/
def doMint (to : Address) (amount : Uint256) : Contract Unit := do
  let currentBal ← getMapping balancesSlot to
  let newBal ← requireSomeUint (safeAdd currentBal amount) "balance overflow"
  let currentSupply ← getStorage totalSupplySlot
  let newSupply ← requireSomeUint (safeAdd currentSupply amount) "supply overflow"
  setMapping balancesSlot to newBal
  setStorage totalSupplySlot newSupply

/--
  Burn tokens from `from`. Decrements `from`'s balance and `totalSupply`.
  Reverts if `from`'s balance is insufficient.
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
  Transfer `amount` tokens from `from` to `to`.
  Enforces transfer restrictions via the whitelist check.
  Reverts with "transfer not allowed" if restrictions are active and neither
  party is whitelisted.
-/
def doTransfer (from : Address) (to : Address) (amount : Uint256) : Contract Unit := do
  -- Enforce transfer restrictions (mint/burn skip this check because from or to is zero)
  let restricted ← getStorage transfersRestrictedSlot
  if from != 0 && to != 0 && restricted then
    let fromWhitelisted ← getMapping transferWhitelistedSlot from
    let toWhitelisted ← getMapping transferWhitelistedSlot to
    require (fromWhitelisted || toWhitelisted) "transfer not allowed"
  else
    pure ()
  -- Perform the transfer
  let fromBal ← getMapping balancesSlot from
  require (fromBal >= amount) "insufficient balance"
  let newFrom ← requireSomeUint (safeSub fromBal amount) "balance underflow"
  let toBal ← getMapping balancesSlot to
  let newTo ← requireSomeUint (safeAdd toBal amount) "balance overflow"
  setMapping balancesSlot from newFrom
  setMapping balancesSlot to newTo

/-! ## Public entrypoints -/

/--
  `mintAllocation(to, amount)` — mints `amount` tokens to `to`.
  Only callable by the minter. Reverts if:
  - `to` is zero address
  - `amount` is zero
  - minting would exceed MAX_SUPPLY
-/
def mintAllocation (to : Address) (amount : Uint256) : Contract Unit := do
  onlyMinter
  require (to != 0) "zero address"
  require (amount != 0) "zero amount"
  let currentMinted ← getStorage totalMintedSlot
  let proposed ← requireSomeUint (safeAdd currentMinted amount) "minted overflow"
  require (proposed <= MAX_SUPPLY) "exceeds total supply"
  doMint to amount
  setStorage totalMintedSlot proposed
  emitEvent "AllocationMinted" [amount] [addressToWord to]

/--
  `disableTransferRestrictions()` — permanently disables transfer restrictions.
  Only callable by the owner. Idempotent: a no-op when already disabled.
  One-way switch: once disabled, restrictions cannot be re-enabled.
-/
def disableTransferRestrictions : Contract Unit := do
  onlyOwner
  let restricted ← getStorage transfersRestrictedSlot
  if restricted then
    setStorage transfersRestrictedSlot false
    emitEvent "TransferRestrictionUpdated" [0] []
  else
    pure ()

/--
  `toggleTransferWhitelist(account)` — flips the whitelist status for `account`.
  Only callable by the whitelist manager.
-/
def toggleTransferWhitelist (account : Address) : Contract Unit := do
  onlyWhitelistManager
  let current ← getMapping transferWhitelistedSlot account
  setMapping transferWhitelistedSlot account (!current)
  emitEvent "TransferWhitelistUpdated" [if !current then 1 else 0] [addressToWord account]

/--
  `transfer(to, amount)` — public transfer function.
  Delegates to the internal `doTransfer` with `msg.sender` as `from`.
-/
def transfer (to : Address) (amount : Uint256) : Contract Unit := do
  let sender ← msgSender
  doTransfer sender to amount
  emitEvent "Transfer" [amount] [addressToWord sender, addressToWord to]

/--
  `whitelistContract(addr)` — whitelists a contract address.
  Only callable by the whitelist manager. Skips zero addresses.
-/
def whitelistContract (addr : Address) : Contract Unit := do
  onlyWhitelistManager
  if addr != 0 then
    setMapping transferWhitelistedSlot addr true
    emitEvent "TransferWhitelistUpdated" [1] [addressToWord addr]
  else
    pure ()

/-! ## Initialization -/

/--
  Initialize the token state. Sets owner, minter, whitelist manager,
  enables transfer restrictions, and whitelists the initial owner.
-/
def initToken (initialOwner : Address) : Contract Unit := do
  setStorageAddr ownerSlot initialOwner
  setStorageAddr minterSlot initialOwner
  setStorageAddr whitelistManagerSlot initialOwner
  setStorage transfersRestrictedSlot true
  setMapping transferWhitelistedSlot initialOwner true
  emitEvent "TransferRestrictionUpdated" [1] []
  emitEvent "TransferWhitelistUpdated" [1] [addressToWord initialOwner]
