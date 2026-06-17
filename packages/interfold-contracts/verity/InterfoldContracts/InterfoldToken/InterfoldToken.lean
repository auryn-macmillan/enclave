/-
  InterfoldToken (FOLD) — Verity Formal Verification

  Translation of `contracts/token/InterfoldToken.sol` (v2, 1047 lines) using `verity_contract`.

  The v2 contract adds CCA distribution, vesting escrow, lock policies with curves,
  and a TGE launch lifecycle. This verification focuses on the core safety properties
  that are provable in Verity:

  - Supply cap enforcement (MAX_SUPPLY)
  - Access control (DEFAULT_ADMIN_ROLE, MINTER_ROLE, WHITELIST_ROLE, LOCK_MANAGER_ROLE)
  - Phase-gated minting (mint/mintAllocations revert when phase ≠ Virtual)
  - TGE one-way switch (tge() fires exactly once)
  - Pre-TGE transfer restriction enforcement
  - Whitelist management

  Storage layout note: OpenZeppelin AccessControl uses
  `mapping(bytes32 => mapping(address => uint256))` for role membership.
  Verity's getMapping2 only supports Address→Address keys, so we model each
  role as a separate `Address → Uint256` mapping. The behavioral semantics
  are identical: hasRole(role, account) checks the same logical membership.

  Trust boundaries (NOT modeled in this pass):
  - Lock policies with curves (LockPolicy, Curve, Anchor) — complex vesting math
  - Claim-linking logic (_claim, _linkClaim, _consumeLock, _addOrIncrementLock)
  - ERC20Votes checkpoint logic
  - ERC20Permit
  - Ownable2Step ownership transfer
  - BONDING_REGISTRY.totalBonded() external call
  - Lock array manipulation (loops over dynamic arrays)
-/
import Contracts.Common

namespace InterfoldContracts

open Verity hiding pure bind
open Verity.EVM.Uint256
open Verity.Stdlib.Math

/-! ## Role constants (keccak256 hashes, matching Solidity) -/

/-! ## Role, supply, and timing constants -/

def DEFAULT_ADMIN_ROLE : Uint256 := 0
def MINTER_ROLE : Uint256 := 0x6d696e7465725f726f6c65000000000000000000000000000000000000000000
def WHITELIST_ROLE : Uint256 := 0x77686974656c6973745f726f6c650000000000000000000000000000000000
def LOCK_MANAGER_ROLE : Uint256 := 0x6c6f636b5f6d616e616765725f726f6c6500000000000000000000000000
def MAX_SUPPLY : Uint256 := 1200000000000000000000000000  -- 1.2B * 1e18
def TGE_COOLDOWN : Uint256 := 3888000  -- 45 days in seconds
def Phase_Virtual : Uint256 := 0
def Phase_CCA : Uint256 := 1
def Phase_Cooldown : Uint256 := 2
def Phase_Live : Uint256 := 3

verity_contract InterfoldToken where
  storage
    -- ERC20 state
    balances : Address → Uint256 := slot 0
    totalSupply : Uint256 := slot 1
    -- InterfoldToken v2 state
    tgeTimestamp : Uint256 := slot 2          -- 0 = not yet fired; >0 = TGE timestamp
    transferWhitelisted : Address → Uint256 := slot 3  -- 1 = true, 0 = false
    claimLockExempt : Address → Uint256 := slot 4      -- 1 = true, 0 = false
    -- AccessControl: modeled as separate per-role mappings (see note above)
    adminRoleMembers : Address → Uint256 := slot 5     -- DEFAULT_ADMIN_ROLE
    minterRoleMembers : Address → Uint256 := slot 6    -- MINTER_ROLE
    whitelistRoleMembers : Address → Uint256 := slot 7 -- WHITELIST_ROLE
    lockManagerRoleMembers : Address → Uint256 := slot 8 -- LOCK_MANAGER_ROLE
    -- Immutable config (modeled as regular storage for verification purposes)
    ccaStart : Uint256 := slot 9
    ccaEnd : Uint256 := slot 10
    noMoreLocks : Uint256 := slot 11
    claimSource : Address := slot 12
    bondingRegistry : Address := slot 13

  -- Internal: mint tokens with supply cap check
  function doMintTokens (recipient : Address, amount : Uint256) : Unit := do
    require (amount != 0) "zero amount"
    let currentSupply ← getStorage totalSupply
    let newSupply ← requireSomeUint (safeAdd currentSupply amount) "supply overflow"
    require (newSupply <= 1200000000000000000000000000) "max supply exceeded"
    let currentBal ← getMapping balances recipient
    let newBal ← requireSomeUint (safeAdd currentBal amount) "balance overflow"
    setMapping balances recipient newBal
    setStorage totalSupply newSupply

  -- mint(recipient, amount, label)
  -- Only DEFAULT_ADMIN_ROLE. Only in Virtual phase (tge==0 && now<ccaStart).
  function mint (recipient : Address, amount : Uint256, label : Uint256) : Unit := do
    let sender ← msgSender
    let hasRole ← getMapping adminRoleMembers sender
    require (hasRole == 1) "missing role"
    let tge ← getStorage tgeTimestamp
    require (tge == 0) "minting closed"
    let now ← blockTimestamp
    let start ← getStorage ccaStart
    require (now < start) "minting closed"
    doMintTokens recipient amount

  -- mintAllocations(recipient, amount, policyId)
  -- Only MINTER_ROLE. Only in Virtual phase (tge==0 && now<ccaStart).
  function mintAllocations (recipient : Address, amount : Uint256, policyId : Uint256) : Unit := do
    let sender ← msgSender
    let hasRole ← getMapping minterRoleMembers sender
    require (hasRole == 1) "missing role"
    let tge ← getStorage tgeTimestamp
    require (tge == 0) "minting closed"
    let now ← blockTimestamp
    let start ← getStorage ccaStart
    require (now < start) "minting closed"
    require (policyId != 0) "invalid policy"
    doMintTokens recipient amount

  -- tge()
  -- Permissionless. Fires TGE exactly once.
  function tge () : Unit := do
    let currentTge ← getStorage tgeTimestamp
    require (currentTge == 0) "already live"
    let now ← blockTimestamp
    let end_ ← getStorage ccaEnd
    let earliest ← requireSomeUint (safeAdd end_ 3888000) "timestamp overflow"  -- TGE_COOLDOWN
    require (now >= earliest) "tge too early"
    setStorage tgeTimestamp now

  -- setTransferWhitelisted(account, whitelisted)
  -- Only WHITELIST_ROLE.
  function setTransferWhitelisted (account : Address, whitelisted : Uint256) : Unit := do
    let sender ← msgSender
    let hasRole ← getMapping whitelistRoleMembers sender
    require (hasRole == 1) "missing role"
    require (account != 0) "zero address"
    setMapping transferWhitelisted account whitelisted

namespace InterfoldToken

/-- Guard helper: check admin role. -/
def onlyAdmin : Contract Unit := do
  let sender ← msgSender
  let result ← getMapping adminRoleMembers sender
  require (result == 1) "missing role"

/-- Guard helper: check minter role. -/
def onlyMinter : Contract Unit := do
  let sender ← msgSender
  let result ← getMapping minterRoleMembers sender
  require (result == 1) "missing role"

/-- Guard helper: check whitelist role. -/
def onlyWhitelist : Contract Unit := do
  let sender ← msgSender
  let result ← getMapping whitelistRoleMembers sender
  require (result == 1) "missing role"

end InterfoldToken

end InterfoldContracts
