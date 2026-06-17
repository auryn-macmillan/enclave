/-
  InterfoldToken (FOLD) — Machine-Checked Proofs

  All theorems are complete — NO `sorry` admissions.

  Proof objectives (see PROOF_OBJECTIVES.md):
  - INTF-P1: doMintTokens reverts when supply cap exceeded
  - INTF-P2: mint reverts when phase ≠ Virtual (tgeTimestamp != 0)
  - INTF-P3: mint reverts when caller lacks DEFAULT_ADMIN_ROLE
  - INTF-P4: mintAllocations reverts when phase ≠ Virtual
  - INTF-P5: mintAllocations reverts when caller lacks MINTER_ROLE
  - INTF-P6: tge() reverts when already live
  - INTF-P7: tge() reverts when called too early
  - INTF-P8: setTransferWhitelisted reverts without WHITELIST_ROLE
  - INTF-P9: isTransferRestricted returns 1 for blocked pre-TGE transfers
  - INTF-P10: isTransferRestricted returns 0 post-TGE
  - INTF-P11: isTransferRestricted returns 0 for mint/burn
-/
import Contracts.InterfoldToken.Spec
import Verity.Proofs.Stdlib.Automation

namespace Contracts.InterfoldToken.Proofs

open Verity
open Verity.EVM.Uint256
open Contracts.InterfoldToken
open Contracts.InterfoldToken.Spec

set_option maxHeartbeats 400000

/-! ## INTF-P1: doMintTokens reverts when supply cap exceeded -/

theorem doMintTokens_revert_cap
    (s : ContractState) (recipient : Address) (amount : Uint256)
    (h_amount : amount ≠ 0)
    (h_exceeds : add (s.storage totalSupply.slot) amount > MAX_SUPPLY) :
    ((doMintTokens recipient amount).run s).fst.isRevert := by
  verity_unfold doMintTokens
  simp only [getStorage, getMapping, require, requireSomeUint, safeAdd, bind,
             totalSupply, balances, MAX_SUPPLY,
             h_amount, h_exceeds]
  exact ContractResult.revert_isRevert _

/-! ## doMintTokens reverts on zero amount -/

theorem doMintTokens_revert_zero
    (s : ContractState) (recipient : Address) :
    ((doMintTokens recipient 0).run s).fst.isRevert := by
  verity_unfold doMintTokens
  simp only [require, bind]
  exact ContractResult.revert_isRevert _

/-! ## INTF-P3: mint reverts without DEFAULT_ADMIN_ROLE -/

theorem mint_revert_no_role
    (s : ContractState) (recipient : Address) (amount : Uint256) (label : Uint256)
    (h_no_role : s.storageMap2 roleMembers.slot DEFAULT_ADMIN_ROLE s.sender ≠ 1) :
    ((mint recipient amount label).run s).fst.isRevert := by
  verity_unfold mint
  simp only [onlyRole, msgSender, getMapping2, require, bind,
             roleMembers, DEFAULT_ADMIN_ROLE, h_no_role]
  exact ContractResult.revert_isRevert _

/-! ## INTF-P2: mint reverts when phase ≠ Virtual (tgeTimestamp != 0 implies Live) -/

theorem mint_revert_not_virtual
    (s : ContractState) (recipient : Address) (amount : Uint256) (label : Uint256)
    (h_role : s.storageMap2 roleMembers.slot DEFAULT_ADMIN_ROLE s.sender = 1)
    (h_live : s.storage tgeTimestamp.slot ≠ 0) :
    ((mint recipient amount label).run s).fst.isRevert := by
  verity_unfold mint
  simp only [onlyRole, msgSender, getMapping2, require, bind,
             roleMembers, DEFAULT_ADMIN_ROLE, h_role]
  -- After onlyRole passes, currentPhase is called
  -- When tgeTimestamp != 0, currentPhase returns Phase_Live
  -- require (phase == Phase_Virtual) fails because phase == Phase_Live
  simp only [currentPhase, getStorage, getBlockTimestamp, if_pos, tgeTimestamp,
             ccaStart, ccaEnd, Phase_Live, h_live]
  exact ContractResult.revert_isRevert _

/-! ## INTF-P5: mintAllocations reverts without MINTER_ROLE -/

theorem mintAllocations_revert_no_role
    (s : ContractState) (recipient : Address) (amount : Uint256) (policyId : Uint256)
    (h_no_role : s.storageMap2 roleMembers.slot MINTER_ROLE s.sender ≠ 1) :
    ((mintAllocations recipient amount policyId).run s).fst.isRevert := by
  verity_unfold mintAllocations
  simp only [onlyRole, msgSender, getMapping2, require, bind,
             roleMembers, MINTER_ROLE, h_no_role]
  exact ContractResult.revert_isRevert _

/-! ## INTF-P4: mintAllocations reverts when phase ≠ Virtual -/

theorem mintAllocations_revert_not_virtual
    (s : ContractState) (recipient : Address) (amount : Uint256) (policyId : Uint256)
    (h_role : s.storageMap2 roleMembers.slot MINTER_ROLE s.sender = 1)
    (h_live : s.storage tgeTimestamp.slot ≠ 0) :
    ((mintAllocations recipient amount policyId).run s).fst.isRevert := by
  verity_unfold mintAllocations
  simp only [onlyRole, msgSender, getMapping2, require, bind,
             roleMembers, MINTER_ROLE, h_role]
  simp only [currentPhase, getStorage, getBlockTimestamp, if_pos, tgeTimestamp,
             ccaStart, ccaEnd, Phase_Live, h_live]
  exact ContractResult.revert_isRevert _

/-! ## INTF-P6: tge() reverts when already live -/

theorem tge_revert_already_live
    (s : ContractState)
    (h_live : s.storage tgeTimestamp.slot ≠ 0) :
    ((tge).run s).fst.isRevert := by
  verity_unfold tge
  simp only [getStorage, require, bind, tgeTimestamp, h_live]
  exact ContractResult.revert_isRevert _

/-! ## INTF-P7: tge() reverts when called too early -/

theorem tge_revert_too_early
    (s : ContractState)
    (h_not_live : s.storage tgeTimestamp.slot = 0)
    (h_early : s.blockTimestamp < add (s.storage ccaEnd.slot) TGE_COOLDOWN) :
    ((tge).run s).fst.isRevert := by
  verity_unfold tge
  simp only [getStorage, require, requireSomeUint, safeAdd, bind,
             tgeTimestamp, ccaEnd, TGE_COOLDOWN,
             h_not_live, h_early]
  exact ContractResult.revert_isRevert _

/-! ## INTF-P8: setTransferWhitelisted reverts without WHITELIST_ROLE -/

theorem setTransferWhitelisted_revert_no_role
    (s : ContractState) (account : Address) (whitelisted : Uint256)
    (h_no_role : s.storageMap2 roleMembers.slot WHITELIST_ROLE s.sender ≠ 1) :
    ((setTransferWhitelisted account whitelisted).run s).fst.isRevert := by
  verity_unfold setTransferWhitelisted
  simp only [onlyRole, msgSender, getMapping2, require, bind,
             roleMembers, WHITELIST_ROLE, h_no_role]
  exact ContractResult.revert_isRevert _

/-! ## setTransferWhitelisted reverts on zero address -/

theorem setTransferWhitelisted_revert_zero
    (s : ContractState) (whitelisted : Uint256)
    (h_role : s.storageMap2 roleMembers.slot WHITELIST_ROLE s.sender = 1) :
    ((setTransferWhitelisted 0 whitelisted).run s).fst.isRevert := by
  verity_unfold setTransferWhitelisted
  simp only [onlyRole, msgSender, getMapping2, require, bind,
             roleMembers, WHITELIST_ROLE, h_role]
  exact ContractResult.revert_isRevert _

/-! ## INTF-P10: isTransferRestricted returns 0 post-TGE -/

theorem isTransferRestricted_post_tge
    (s : ContractState) (from to : Address)
    (h_live : s.storage tgeTimestamp.slot ≠ 0) :
    ((isTransferRestricted from to).run s).fst = ContractResult.success 0 s := by
  verity_unfold isTransferRestricted
  simp only [getStorage, if_pos, tgeTimestamp, h_live]

/-! ## INTF-P11: isTransferRestricted returns 0 for mint (from=0) -/

theorem isTransferRestricted_mint_exempt
    (s : ContractState) (to : Address)
    (h_not_live : s.storage tgeTimestamp.slot = 0) :
    ((isTransferRestricted 0 to).run s).fst = ContractResult.success 0 s := by
  verity_unfold isTransferRestricted
  simp only [getStorage, if_pos, if_neg, tgeTimestamp, h_not_live]

/-! ## INTF-P11: isTransferRestricted returns 0 for burn (to=0) -/

theorem isTransferRestricted_burn_exempt
    (s : ContractState) (from : Address)
    (h_not_live : s.storage tgeTimestamp.slot = 0) :
    ((isTransferRestricted from 0).run s).fst = ContractResult.success 0 s := by
  verity_unfold isTransferRestricted
  simp only [getStorage, if_pos, if_neg, tgeTimestamp, h_not_live]

/-! ## INTF-P9: isTransferRestricted returns 1 for blocked transfers -/

theorem isTransferRestricted_blocks
    (s : ContractState) (from to : Address)
    (h_not_live : s.storage tgeTimestamp.slot = 0)
    (h_from : from ≠ 0)
    (h_to : to ≠ 0)
    (h_not_bonding_from : from ≠ s.storageAddr bondingRegistry.slot)
    (h_not_bonding_to : to ≠ s.storageAddr bondingRegistry.slot)
    (h_not_cca : from ≠ s.storageAddr claimSource.slot)
    (h_from_not_wl : s.storageMap transferWhitelisted.slot from = 0)
    (h_to_not_wl : s.storageMap transferWhitelisted.slot to = 0) :
    ((isTransferRestricted from to).run s).fst = ContractResult.success 1 s := by
  verity_unfold isTransferRestricted
  simp only [getStorage, getStorageAddr, getMapping, if_pos, if_neg,
             tgeTimestamp, transferWhitelisted, bondingRegistry, claimSource,
             h_not_live, h_from, h_to,
             h_not_bonding_from, h_not_bonding_to, h_not_cca,
             h_from_not_wl, h_to_not_wl]

end Contracts.InterfoldToken.Proofs
