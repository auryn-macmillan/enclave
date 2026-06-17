/-
  InterfoldTicketToken — Formal Specifications

  Each spec is a Prop-valued predicate over pre/post ContractState.
  Specs describe WHAT the function does, not HOW.

  Proof objectives covered:
  - ITK-P1: Registry-guarded functions revert on wrong caller
  - ITK-P2: burnTickets accounting
  - ITK-P3: payout bounds check
  - ITK-P4: payout accounting
  - ITK-P5: _update non-transferability
  - ITK-P6: approve always revert
  - ITK-P7: permit always revert
  - ITK-P8: delegate only self
  - ITK-P9: activateRegistryChange timelock
  - ITK-P10: lockRegistry one-way
  - ITK-P11: setRegistry locked revert
  - ITK-P12: requestRegistryChange not-locked revert
  - ITK-PEG: Peg invariant
-/
import Verity.Specs.Common
import Verity.Macro
import Contracts.InterfoldTicketToken.InterfoldTicketToken

namespace Contracts.InterfoldTicketToken.Spec

open Verity
open Verity.EVM.Uint256
open Contracts.InterfoldTicketToken

/-! ## ITK-P1: Registry-guarded function revert specs -/

/-- depositFor reverts when msg.sender ≠ registry. -/
def depositFor_revert_not_registry (operator : Address) (amount : Uint256) (s : ContractState) : Prop :=
  s.sender ≠ s.storageAddr registry.slot →
  ((depositFor operator amount).run s).fst.isRevert

/-- depositFrom reverts when msg.sender ≠ registry. -/
def depositFrom_revert_not_registry (from to : Address) (amount : Uint256) (s : ContractState) : Prop :=
  s.sender ≠ s.storageAddr registry.slot →
  ((depositFrom from to amount).run s).fst.isRevert

/-- withdrawTo reverts when msg.sender ≠ registry. -/
def withdrawTo_revert_not_registry (receiver : Address) (amount : Uint256) (s : ContractState) : Prop :=
  s.sender ≠ s.storageAddr registry.slot →
  ((withdrawTo receiver amount).run s).fst.isRevert

/-- burnTickets reverts when msg.sender ≠ registry. -/
def burnTickets_revert_not_registry (operator : Address) (amount : Uint256) (s : ContractState) : Prop :=
  s.sender ≠ s.storageAddr registry.slot →
  ((burnTickets operator amount).run s).fst.isRevert

/-- payout reverts when msg.sender ≠ registry. -/
def payout_revert_not_registry (to : Address) (amount : Uint256) (s : ContractState) : Prop :=
  s.sender ≠ s.storageAddr registry.slot →
  ((payout to amount).run s).fst.isRevert

/-! ## ITK-P2: burnTickets accounting spec -/

/-- On success, burnTickets: payableBalance += amount, balances[operator] -= amount,
    totalSupply -= amount, underlyingBal unchanged. -/
def burnTickets_accounting (operator : Address) (amount : Uint256) (s s' : ContractState) : Prop :=
  (s.sender = s.storageAddr registry.slot ∧ operator ≠ 0 ∧ amount ≠ 0) →
    s'.storage payableBalance.slot =
      add (s.storage payableBalance.slot) amount ∧
    s'.storageMap balances.slot operator =
      sub (s.storageMap balances.slot operator) amount ∧
    s'.storage totalSupply.slot =
      sub (s.storage totalSupply.slot) amount ∧
    s'.storage underlyingBal.slot =
      s.storage underlyingBal.slot

/-! ## ITK-P3: payout reverts when underfunded -/

/-- payout reverts when amount > payableBalance. -/
def payout_revert_underfunded (to : Address) (amount : Uint256) (s : ContractState) : Prop :=
  (s.sender = s.storageAddr registry.slot ∧
   amount > s.storage payableBalance.slot) →
  ((payout to amount).run s).fst.isRevert

/-! ## ITK-P4: payout accounting spec -/

/-- On success, payout: payableBalance -= amount, underlyingBal -= amount. -/
def payout_accounting (to : Address) (amount : Uint256) (s s' : ContractState) : Prop :=
  (s.sender = s.storageAddr registry.slot ∧ amount ≠ 0 ∧
   amount ≤ s.storage payableBalance.slot) →
    s'.storage payableBalance.slot =
      sub (s.storage payableBalance.slot) amount ∧
    s'.storage underlyingBal.slot =
      sub (s.storage underlyingBal.slot) amount

/-! ## ITK-P5: doUpdate non-transferability -/

/-- doUpdate reverts when from ≠ 0 and to ≠ 0 (non-transferable). -/
def doUpdate_revert_transfer (from to : Address) (value : Uint256) (s : ContractState) : Prop :=
  (from ≠ 0 ∧ to ≠ 0) →
  ((doUpdate from to value).run s).fst.isRevert

/-- Mint (from=0) does NOT revert due to transfer restriction. -/
def doUpdate_mint_exempt (to : Address) (value : Uint256) (s : ContractState) : Prop :=
  ((doUpdate 0 to value).run s).fst.isRevert →
  ((doUpdate 0 to value).run s).fst = ContractResult.revert "transfer not allowed" s → False

/-- Burn (to=0) does NOT revert due to transfer restriction. -/
def doUpdate_burn_exempt (from : Address) (value : Uint256) (s : ContractState) : Prop :=
  ((doUpdate from 0 value).run s).fst.isRevert →
  ((doUpdate from 0 value).run s).fst = ContractResult.revert "transfer not allowed" s → False

/-! ## ITK-P6: approve always revert -/

/-- approve always reverts (allowances are disabled on this token). -/
def approve_always_revert (spender : Address) (amount : Uint256) (s : ContractState) : Prop :=
  ((approve spender amount).run s).fst.isRevert

/-! ## ITK-P7: permit always revert -/

/-- permit always reverts (ERC-2612 is disabled). -/
def permit_always_revert (owner spender : Address) (value deadline v r s' : Uint256) (st : ContractState) : Prop :=
  ((permit owner spender value deadline v r s').run st).fst.isRevert

/-! ## ITK-P8: delegate only self -/

/-- delegate reverts when delegatee ≠ msg.sender. -/
def delegate_revert_not_self (delegatee : Address) (s : ContractState) : Prop :=
  delegatee ≠ s.sender →
  ((delegate delegatee).run s).fst.isRevert

/-! ## ITK-P9: activateRegistryChange timelock revert -/

/-- activateRegistryChange reverts when block.timestamp < pendingRegistryActivationTime. -/
def activateRegistryChange_revert_before_timelock (s : ContractState) : Prop :=
  (s.sender = s.storageAddr owner.slot ∧
   s.storageAddr pendingRegistry.slot ≠ 0 ∧
   s.blockTimestamp < s.storage pendingRegistryActivationTime.slot) →
  ((activateRegistryChange).run s).fst.isRevert

/-! ## ITK-P10: lockRegistry one-way switch -/

/-- lockRegistry sets registryLocked from 0 to 1 when unlocked. -/
def lockRegistry_sets_locked (s s' : ContractState) : Prop :=
  (s.sender = s.storageAddr owner.slot ∧ s.storage registryLocked.slot = 0) →
    s'.storage registryLocked.slot = 1

/-- lockRegistry reverts when already locked. -/
def lockRegistry_revert_already_locked (s : ContractState) : Prop :=
  (s.storage registryLocked.slot = 1) →
  ((lockRegistry).run s).fst.isRevert

/-! ## ITK-P11: setRegistry revert when locked -/

/-- setRegistry reverts when registryLocked == 1. -/
def setRegistry_revert_when_locked (newRegistry : Address) (s : ContractState) : Prop :=
  (s.sender = s.storageAddr owner.slot ∧ s.storage registryLocked.slot = 1) →
  ((setRegistry newRegistry).run s).fst.isRevert

/-! ## ITK-P12: requestRegistryChange revert when not locked -/

/-- requestRegistryChange reverts when registryLocked == 0. -/
def requestRegistryChange_revert_when_not_locked (newRegistry : Address) (s : ContractState) : Prop :=
  (s.sender = s.storageAddr owner.slot ∧ s.storage registryLocked.slot = 0) →
  ((requestRegistryChange newRegistry).run s).fst.isRevert

/-! ## ITK-PEG: Peg invariant

The 1:1 peg is a conservation-of-value invariant. The underlying token balance
held by the contract must equal the sum of all outstanding ITK tokens (totalSupply)
plus slashed funds earmarked for payout (payableBalance). In accounting terms:
Assets (underlyingBal) = Equity (totalSupply) + Liabilities (payableBalance).

NOTE: The PROOF_OBJECTIVES.md states "totalSupply == underlyingBal + payableBalance",
which is a reversed equation that does NOT hold for burnTickets or payout.
The correct and verifiable equation is "underlyingBal == totalSupply + payableBalance",
equivalently totalSupply + payableBalance == underlyingBal.

Verified preservation:
  - depositFor/From: totalSupply += amt, underlyingBal += amt → ✓
  - withdrawTo:       totalSupply -= amt, underlyingBal -= amt → ✓
  - burnTickets:      totalSupply -= amt, payableBal += amt, underlyingBal unchanged → ✓
  - payout:           payableBal -= amt, underlyingBal -= amt, totalSupply unchanged → ✓
-/

/-- The peg: underlyingBal == totalSupply + payableBalance. -/
def peg_invariant (s : ContractState) : Prop :=
  s.storage underlyingBal.slot = add (s.storage totalSupply.slot) (s.storage payableBalance.slot)

/-- Peg invariant preserved by depositFor. -/
def peg_preserved_by_depositFor (operator : Address) (amount : Uint256) (s : ContractState) : Prop :=
  (peg_invariant s) →
  peg_invariant ((depositFor operator amount).run s).snd

/-- Peg invariant preserved by depositFrom. -/
def peg_preserved_by_depositFrom (from to : Address) (amount : Uint256) (s : ContractState) : Prop :=
  (peg_invariant s) →
  peg_invariant ((depositFrom from to amount).run s).snd

/-- Peg invariant preserved by withdrawTo. -/
def peg_preserved_by_withdrawTo (receiver : Address) (amount : Uint256) (s : ContractState) : Prop :=
  (peg_invariant s) →
  peg_invariant ((withdrawTo receiver amount).run s).snd

/-- Peg invariant preserved by burnTickets. -/
def peg_preserved_by_burnTickets (operator : Address) (amount : Uint256) (s : ContractState) : Prop :=
  (peg_invariant s) →
  peg_invariant ((burnTickets operator amount).run s).snd

/-- Peg invariant preserved by payout. -/
def peg_preserved_by_payout (to : Address) (amount : Uint256) (s : ContractState) : Prop :=
  (peg_invariant s) →
  peg_invariant ((payout to amount).run s).snd

end Contracts.InterfoldTicketToken.Spec
