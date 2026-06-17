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

namespace Contracts.InterfoldToken

open Verity hiding pure bind
open Verity.EVM.Uint256

/-! ## Role constants -/

def DEFAULT_ADMIN_ROLE : Uint256 := 0
def MINTER_ROLE : Uint256 := 0x6d696e7465725f726f6c65000000000000000000000000000000000000000000
def WHITELIST_ROLE : Uint256 := 0x77686974656c6973745f726f6c650000000000000000000000000000000000
def LOCK_MANAGER_ROLE : Uint256 := 0x6c6f636b5f6d616e616765725f726f6c6500000000000000000000000000

/-! ## Supply and timing constants -/

def MAX_SUPPLY : Uint256 := 1200000000000000000000000000  -- 1.2B * 1e18
def TGE_COOLDOWN : Uint256 := 3888000  -- 45 days in seconds

/-! ## Phase enum (as Uint256) -/

def Phase_Virtual : Uint256 := 0
def Phase_CCA : Uint256 := 1
def Phase_Cooldown : Uint256 := 2
def Phase_Live : Uint256 := 3

/-! ## Contract -/

verity_contract InterfoldToken where
  storage
    -- ERC20 state
    balances : Address -> Uint256 := slot 0
    totalSupply : Uint256 := slot 1
    -- InterfoldToken v2 state
    tgeTimestamp : Uint256 := slot 2          -- 0 = not yet fired; >0 = TGE timestamp
    transferWhitelisted : Address -> Uint256 := slot 3  -- 1 = true, 0 = false
    claimLockExempt : Address -> Uint256 := slot 4      -- 1 = true, 0 = false
    -- AccessControl: roleMembers[role][account] = 1 if account has role
    roleMembers : Uint256 -> Address -> Uint256 := slot 5
    -- Immutable config (modeled as regular storage for verification purposes)
    ccaStart : Uint256 := slot 6
    ccaEnd : Uint256 := slot 7
    noMoreLocks : Uint256 := slot 8
    claimSource : Address := slot 9
    bondingRegistry : Address := slot 10

  -- Guard: check that caller has a specific role
  function onlyRole (role : Uint256) : Unit := do
    let sender ← msgSender
    let hasRole ← getMapping2 roleMembers role sender
    require (hasRole == 1) "missing role"

  -- Current lifecycle phase (view function)
  function currentPhase : Uint256 := do
    let tge ← getStorage tgeTimestamp
    if tge != 0 then
      return Phase_Live
    else
      let now ← getBlockTimestamp
      let start ← getStorage ccaStart
      let end_ ← getStorage ccaEnd
      if now < start then
        return Phase_Virtual
      else if now < end_ then
        return Phase_CCA
      else
        return Phase_Cooldown

  -- Internal: mint tokens with supply cap check
  function doMintTokens (recipient : Address) (amount : Uint256) : Unit := do
    require (amount != 0) "zero amount"
    let currentSupply ← getStorage totalSupply
    let newSupply ← requireSomeUint (safeAdd currentSupply amount) "supply overflow"
    require (newSupply <= MAX_SUPPLY) "max supply exceeded"
    let currentBal ← getMapping balances recipient
    let newBal ← requireSomeUint (safeAdd currentBal amount) "balance overflow"
    setMapping balances recipient newBal
    setStorage totalSupply newSupply

  -- mint(recipient, amount, label)
  -- Only DEFAULT_ADMIN_ROLE. Only in Virtual phase.
  function mint (recipient : Address) (amount : Uint256) (label : Uint256) : Unit := do
    onlyRole DEFAULT_ADMIN_ROLE
    let phase ← currentPhase
    require (phase == Phase_Virtual) "minting closed"
    doMintTokens recipient amount
    emitEvent "AllocationMinted" [amount] [addressToWord recipient]

  -- mintAllocations(recipient, amount, policyId)
  -- Only MINTER_ROLE. Only in Virtual phase.
  function mintAllocations (recipient : Address) (amount : Uint256) (policyId : Uint256) : Unit := do
    onlyRole MINTER_ROLE
    let phase ← currentPhase
    require (phase == Phase_Virtual) "minting closed"
    require (policyId != 0) "invalid policy"
    doMintTokens recipient amount
    emitEvent "AllocationMinted" [amount] [addressToWord recipient]

  -- tge()
  -- Permissionless. Fires TGE exactly once.
  function tge : Unit := do
    let currentTge ← getStorage tgeTimestamp
    require (currentTge == 0) "already live"
    let now ← getBlockTimestamp
    let end_ ← getStorage ccaEnd
    let earliest ← requireSomeUint (safeAdd end_ TGE_COOLDOWN) "timestamp overflow"
    require (now >= earliest) "tge too early"
    setStorage tgeTimestamp now
    emitEvent "TgeTriggered" [now] []

  -- setTransferWhitelisted(account, whitelisted)
  -- Only WHITELIST_ROLE.
  function setTransferWhitelisted (account : Address) (whitelisted : Uint256) : Unit := do
    onlyRole WHITELIST_ROLE
    require (account != 0) "zero address"
    setMapping transferWhitelisted account whitelisted
    emitEvent "TransferWhitelistUpdated" [whitelisted] [addressToWord account]

  -- isTransferRestricted(from, to)
  -- Returns 1 if transfer is blocked by pre-TGE gate, 0 otherwise.
  function isTransferRestricted (from to : Address) : Uint256 := do
    let tge ← getStorage tgeTimestamp
    if tge != 0 then
      return 0
    else if from == 0 || to == 0 then
      return 0
    else
      let registry ← getStorageAddr bondingRegistry
      let isBonding := (from == registry) || (to == registry)
      let source ← getStorageAddr claimSource
      let isCcaDistribution := (from == source)
      let fromWl ← getMapping transferWhitelisted from
      let toWl ← getMapping transferWhitelisted to
      let isWhitelisted := (fromWl == 1) || (toWl == 1)
      if !isBonding && !isCcaDistribution && !isWhitelisted then
        return 1
      else
        return 0

end Contracts.InterfoldToken
