/-
  InterfoldToken (FOLD) — Formal Specifications

  Specs for the v2 contract: supply cap, access control, phase-gated minting,
  TGE one-way switch, and transfer restriction logic.
-/
import Verity.Specs.Common
import Verity.Macro
import Contracts.InterfoldToken.InterfoldToken

namespace Contracts.InterfoldToken.Spec

open Verity
open Verity.EVM.Uint256
open Contracts.InterfoldToken

/-- doMintTokens reverts when totalSupply + amount > MAX_SUPPLY. -/
def doMintTokens_revert_cap (recipient : Address) (amount : Uint256) (s : ContractState) : Prop :=
  (amount ≠ 0 ∧ add (s.storage totalSupply.slot) amount > MAX_SUPPLY) →
  ((doMintTokens recipient amount).run s).fst.isRevert

/-- doMintTokens reverts when amount == 0. -/
def doMintTokens_revert_zero (recipient : Address) (s : ContractState) : Prop :=
  ((doMintTokens recipient 0).run s).fst.isRevert

/-- mint reverts when caller lacks DEFAULT_ADMIN_ROLE. -/
def mint_revert_no_role (recipient : Address) (amount : Uint256) (label : Uint256) (s : ContractState) : Prop :=
  (s.storageMap2 roleMembers.slot DEFAULT_ADMIN_ROLE s.sender ≠ 1) →
  ((mint recipient amount label).run s).fst.isRevert

/-- mint reverts when phase ≠ Virtual. -/
def mint_revert_not_virtual (recipient : Address) (amount : Uint256) (label : Uint256) (s : ContractState) : Prop :=
  (s.storageMap2 roleMembers.slot DEFAULT_ADMIN_ROLE s.sender = 1 ∧
   s.storage tgeTimestamp.slot ≠ 0) →
  ((mint recipient amount label).run s).fst.isRevert

/-- mintAllocations reverts when caller lacks MINTER_ROLE. -/
def mintAllocations_revert_no_role (recipient : Address) (amount : Uint256) (policyId : Uint256) (s : ContractState) : Prop :=
  (s.storageMap2 roleMembers.slot MINTER_ROLE s.sender ≠ 1) →
  ((mintAllocations recipient amount policyId).run s).fst.isRevert

/-- mintAllocations reverts when phase ≠ Virtual. -/
def mintAllocations_revert_not_virtual (recipient : Address) (amount : Uint256) (policyId : Uint256) (s : ContractState) : Prop :=
  (s.storageMap2 roleMembers.slot MINTER_ROLE s.sender = 1 ∧
   s.storage tgeTimestamp.slot ≠ 0) →
  ((mintAllocations recipient amount policyId).run s).fst.isRevert

/-- tge() reverts when already live (tgeTimestamp != 0). -/
def tge_revert_already_live (s : ContractState) : Prop :=
  (s.storage tgeTimestamp.slot ≠ 0) →
  ((tge).run s).fst.isRevert

/-- tge() reverts when called before CCA_END + TGE_COOLDOWN. -/
def tge_revert_too_early (s : ContractState) : Prop :=
  (s.storage tgeTimestamp.slot = 0 ∧
   s.blockTimestamp < add (s.storage ccaEnd.slot) TGE_COOLDOWN) →
  ((tge).run s).fst.isRevert

/-- tge() sets tgeTimestamp on success. -/
def tge_sets_timestamp (s s' : ContractState) : Prop :=
  (s.storage tgeTimestamp.slot = 0 ∧
   s.blockTimestamp >= add (s.storage ccaEnd.slot) TGE_COOLDOWN) →
  s'.storage tgeTimestamp.slot = s.blockTimestamp

/-- setTransferWhitelisted reverts when caller lacks WHITELIST_ROLE. -/
def setTransferWhitelisted_revert_no_role (account : Address) (whitelisted : Uint256) (s : ContractState) : Prop :=
  (s.storageMap2 roleMembers.slot WHITELIST_ROLE s.sender ≠ 1) →
  ((setTransferWhitelisted account whitelisted).run s).fst.isRevert

/-- setTransferWhitelisted reverts when account is zero address. -/
def setTransferWhitelisted_revert_zero (whitelisted : Uint256) (s : ContractState) : Prop :=
  (s.storageMap2 roleMembers.slot WHITELIST_ROLE s.sender = 1) →
  ((setTransferWhitelisted 0 whitelisted).run s).fst.isRevert

/-- setTransferWhitelisted sets the whitelist status on success. -/
def setTransferWhitelisted_sets (account : Address) (whitelisted : Uint256) (s s' : ContractState) : Prop :=
  (s.storageMap2 roleMembers.slot WHITELIST_ROLE s.sender = 1 ∧ account ≠ 0) →
  s'.storageMap transferWhitelisted.slot account = whitelisted

/-- isTransferRestricted returns 0 (not restricted) when tgeTimestamp != 0 (post-TGE). -/
def isTransferRestricted_post_tge (from to : Address) (s : ContractState) : Prop :=
  (s.storage tgeTimestamp.slot ≠ 0) →
  ((isTransferRestricted from to).run s).fst = ContractResult.success 0 s

/-- isTransferRestricted returns 0 when from == 0 (mint). -/
def isTransferRestricted_mint_exempt (to : Address) (s : ContractState) : Prop :=
  ((isTransferRestricted 0 to).run s).fst = ContractResult.success 0 s

/-- isTransferRestricted returns 0 when to == 0 (burn). -/
def isTransferRestricted_burn_exempt (from : Address) (s : ContractState) : Prop :=
  ((isTransferRestricted from 0).run s).fst = ContractResult.success 0 s

/-- isTransferRestricted returns 1 when pre-TGE, non-mint/burn, non-bonding, non-CCA, non-whitelisted. -/
def isTransferRestricted_blocks (from to : Address) (s : ContractState) : Prop :=
  (s.storage tgeTimestamp.slot = 0 ∧
   from ≠ 0 ∧ to ≠ 0 ∧
   from ≠ s.storageAddr bondingRegistry.slot ∧
   to ≠ s.storageAddr bondingRegistry.slot ∧
   from ≠ s.storageAddr claimSource.slot ∧
   s.storageMap transferWhitelisted.slot from = 0 ∧
   s.storageMap transferWhitelisted.slot to = 0) →
  ((isTransferRestricted from to).run s).fst = ContractResult.success 1 s

/-- Supply cap invariant: totalSupply ≤ MAX_SUPPLY. -/
def supply_cap_invariant (s : ContractState) : Prop :=
  s.storage totalSupply.slot ≤ MAX_SUPPLY

end Contracts.InterfoldToken.Spec
