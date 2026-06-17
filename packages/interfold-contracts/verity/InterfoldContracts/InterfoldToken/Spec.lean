/-
  InterfoldToken (FOLD) — Formal Specifications

  Specs for the v2 contract: supply cap, access control, phase-gated minting,
  TGE one-way switch, and transfer restriction logic.

  All revert specs use the real Verity ContractResult shape:
  `∃ msg, (fn).run s = ContractResult.revert msg s`
-/
import InterfoldContracts.InterfoldToken.InterfoldToken

namespace InterfoldContracts.InterfoldToken.Spec

open Verity
open Verity.EVM.Uint256
open InterfoldContracts.InterfoldToken

/-- doMintTokens reverts when amount == 0. -/
def doMintTokens_revert_zero (recipient : Address) (s : ContractState) : Prop :=
  ∃ msg, (doMintTokens recipient 0).run s = ContractResult.revert msg s

/-- doMintTokens reverts when totalSupply + amount > MAX_SUPPLY. -/
def doMintTokens_revert_cap (recipient : Address) (amount : Uint256) (s : ContractState) : Prop :=
  (amount ≠ 0 ∧ (s.storage totalSupply.slot : Nat) + (amount : Nat) > (MAX_SUPPLY : Nat)) →
  ∃ msg, (doMintTokens recipient amount).run s = ContractResult.revert msg s

/-- mint reverts when caller lacks DEFAULT_ADMIN_ROLE. -/
def mint_revert_no_role (recipient : Address) (amount : Uint256) (label : Uint256) (s : ContractState) : Prop :=
  (s.storageMap adminRoleMembers.slot s.sender ≠ 1) →
  ∃ msg, (mint recipient amount label).run s = ContractResult.revert msg s

/-- mint reverts when phase ≠ Virtual (tgeTimestamp ≠ 0). -/
def mint_revert_not_virtual (recipient : Address) (amount : Uint256) (label : Uint256) (s : ContractState) : Prop :=
  (s.storageMap adminRoleMembers.slot s.sender = 1 ∧
   s.storage tgeTimestamp.slot ≠ 0) →
  ∃ msg, (mint recipient amount label).run s = ContractResult.revert msg s

/-- mintAllocations reverts when caller lacks MINTER_ROLE. -/
def mintAllocations_revert_no_role (recipient : Address) (amount : Uint256) (policyId : Uint256) (s : ContractState) : Prop :=
  (s.storageMap minterRoleMembers.slot s.sender ≠ 1) →
  ∃ msg, (mintAllocations recipient amount policyId).run s = ContractResult.revert msg s

/-- mintAllocations reverts when phase ≠ Virtual (tgeTimestamp ≠ 0). -/
def mintAllocations_revert_not_virtual (recipient : Address) (amount : Uint256) (policyId : Uint256) (s : ContractState) : Prop :=
  (s.storageMap minterRoleMembers.slot s.sender = 1 ∧
   s.storage tgeTimestamp.slot ≠ 0) →
  ∃ msg, (mintAllocations recipient amount policyId).run s = ContractResult.revert msg s

/-- tge() reverts when already live (tgeTimestamp != 0). -/
def tge_revert_already_live (s : ContractState) : Prop :=
  (s.storage tgeTimestamp.slot ≠ 0) →
  ∃ msg, tge.run s = ContractResult.revert msg s

/-- setTransferWhitelisted reverts when caller lacks WHITELIST_ROLE. -/
def setTransferWhitelisted_revert_no_role (account : Address) (whitelisted : Uint256) (s : ContractState) : Prop :=
  (s.storageMap whitelistRoleMembers.slot s.sender ≠ 1) →
  ∃ msg, (setTransferWhitelisted account whitelisted).run s = ContractResult.revert msg s

/-- setTransferWhitelisted reverts when account is zero address. -/
def setTransferWhitelisted_revert_zero (whitelisted : Uint256) (s : ContractState) : Prop :=
  (s.storageMap whitelistRoleMembers.slot s.sender = 1) →
  ∃ msg, (setTransferWhitelisted 0 whitelisted).run s = ContractResult.revert msg s

end InterfoldContracts.InterfoldToken.Spec
