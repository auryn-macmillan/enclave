/-
  InterfoldTicketToken — Machine-Checked Proofs

  Proves that each EDSL function satisfies its specification.
  Focus: peg maintenance, access control enforcement, transfer blocking,
  and registry timelock correctness.
-/
import Verity.Core
import Verity.Specs.Common
import InterfoldTicketToken.InterfoldTicketToken
import InterfoldTicketToken.Spec

open Verity

set_option maxHeartbeats 400000

/-! ## depositFor meets its spec -/

theorem depositFor_meets_spec
    (s : ContractState) (operator : Address) (amount : Uint256)
    (h_registry : s.sender = s.storageAddr registrySlot.slot)
    (h_op_nonzero : operator ≠ 0)
    (h_amount_nonzero : amount ≠ 0) :
    let s' := ((depositFor operator amount).run s).snd
    depositFor_spec operator amount s s' := by
  unfold depositFor depositFor_spec
  unfold onlyRegistry doMint
  simp [msgSender, getStorageAddr, getMapping, setMapping,
        getStorage, setStorage, require, requireSomeUint,
        safeAdd, bind, pure,
        balancesSlot, totalSupplySlot, underlyingBalSlot,
        registrySlot, ownerSlot, payableBalanceSlot,
        h_registry, h_op_nonzero, h_amount_nonzero,
        Specs.storageMapUnchangedExceptKeyAtSlot,
        Specs.sameStorageAddrContext,
        Specs.sameContext,
        Specs.sameStorageContext]

/--
  Theorem: `depositFor` reverts when called by non-registry.
-/
theorem depositFor_reverts_non_registry
    (s : ContractState) (operator : Address) (amount : Uint256)
    (h_not_registry : s.sender ≠ s.storageAddr registrySlot.slot) :
    ((depositFor operator amount).run s).fst.isRevert := by
  unfold depositFor onlyRegistry
  simp [msgSender, getStorageAddr, registrySlot, require, bind, h_not_registry]

/--
  Theorem: `depositFor` reverts when operator is zero address.
-/
theorem depositFor_reverts_zero_operator
    (s : ContractState) (amount : Uint256)
    (h_registry : s.sender = s.storageAddr registrySlot.slot) :
    ((depositFor 0 amount).run s).fst.isRevert := by
  unfold depositFor onlyRegistry
  simp [msgSender, getStorageAddr, registrySlot, require, bind, h_registry]

/--
  Theorem: `depositFor` maintains the peg invariant.
  If peg holds before deposit, it holds after.
-/
theorem depositFor_preserves_peg
    (s : ContractState) (operator : Address) (amount : Uint256)
    (h_registry : s.sender = s.storageAddr registrySlot.slot)
    (h_op_nonzero : operator ≠ 0)
    (h_amount_nonzero : amount ≠ 0)
    (h_peg : peg_invariant s)
    (h_success : ((depositFor operator amount).run s).fst.isSuccess) :
    peg_invariant ((depositFor operator amount).run s).snd := by
  have h_spec := depositFor_meets_spec s operator amount
    h_registry h_op_nonzero h_amount_nonzero
  unfold peg_invariant
  -- Both totalSupply and underlyingBal increase by amount, so their relationship holds
  -- totalSupply' = totalSupply + amount
  -- underlyingBal' + payableBalance' = (underlyingBal + amount) + payableBalance
  -- = (totalSupply) + amount  (by h_peg: totalSupply = underlyingBal + payableBalance)
  -- = totalSupply'
  unfold depositFor_spec at h_spec
  obtain ⟨_, h_supply, h_underlying, _, _, _⟩ := h_spec s (rfl)
  rw [h_supply, h_underlying]
  rw [h_peg]
  ring

/-! ## burnTickets meets its spec -/

theorem burnTickets_meets_spec
    (s : ContractState) (operator : Address) (amount : Uint256)
    (h_registry : s.sender = s.storageAddr registrySlot.slot)
    (h_op_nonzero : operator ≠ 0)
    (h_amount_nonzero : amount ≠ 0)
    (h_balance : s.storageMap balancesSlot.slot operator >= amount) :
    let s' := ((burnTickets operator amount).run s).snd
    burnTickets_spec operator amount s s' := by
  unfold burnTickets burnTickets_spec
  unfold onlyRegistry doBurn
  simp [msgSender, getStorageAddr, getMapping, setMapping,
        getStorage, setStorage, require, requireSomeUint,
        safeAdd, safeSub, bind, pure,
        balancesSlot, totalSupplySlot, underlyingBalSlot,
        payableBalanceSlot, registrySlot,
        h_registry, h_op_nonzero, h_amount_nonzero, h_balance,
        Specs.storageMapUnchangedExceptKeyAtSlot,
        Specs.sameStorageAddrContext,
        Specs.sameContext,
        Specs.sameStorageContext]

/--
  Theorem: `burnTickets` preserves the peg invariant.
  totalSupply decreases by amount, payableBalance increases by amount,
  underlyingBal unchanged → peg maintained.
-/
theorem burnTickets_preserves_peg
    (s : ContractState) (operator : Address) (amount : Uint256)
    (h_registry : s.sender = s.storageAddr registrySlot.slot)
    (h_op_nonzero : operator ≠ 0)
    (h_amount_nonzero : amount ≠ 0)
    (h_balance : s.storageMap balancesSlot.slot operator >= amount)
    (h_peg : peg_invariant s)
    (h_success : ((burnTickets operator amount).run s).fst.isSuccess) :
    peg_invariant ((burnTickets operator amount).run s).snd := by
  have h_spec := burnTickets_meets_spec s operator amount
    h_registry h_op_nonzero h_amount_nonzero h_balance
  unfold peg_invariant
  unfold burnTickets_spec at h_spec
  obtain ⟨_, h_supply, h_underlying, h_payable, _, _, _⟩ := h_spec s (rfl)
  rw [h_supply, h_underlying, h_payable]
  rw [h_peg]
  ring

/-! ## lockRegistry meets its spec -/

theorem lockRegistry_meets_spec
    (s : ContractState)
    (h_owner : s.sender = s.storageAddr ownerSlot.slot)
    (h_not_locked : s.storage registryLockedSlot.slot = false) :
    ((lockRegistry).run s).snd.storage registryLockedSlot.slot = true := by
  unfold lockRegistry onlyOwner
  simp [msgSender, getStorageAddr, getStorage, setStorage,
        ownerSlot, registryLockedSlot, require, bind,
        h_owner, h_not_locked]

/--
  Theorem: `lockRegistry` reverts when already locked.
-/
theorem lockRegistry_reverts_already_locked
    (s : ContractState)
    (h_owner : s.sender = s.storageAddr ownerSlot.slot)
    (h_locked : s.storage registryLockedSlot.slot = true) :
    ((lockRegistry).run s).fst.isRevert := by
  unfold lockRegistry onlyOwner
  simp [msgSender, getStorageAddr, getStorage, ownerSlot, registryLockedSlot,
        require, bind, h_owner, h_locked]

/-! ## activateRegistryChange meets its spec -/

theorem activateRegistryChange_meets_spec
    (s : ContractState)
    (h_owner : s.sender = s.storageAddr ownerSlot.slot)
    (h_pending : s.storageAddr pendingRegistrySlot.slot ≠ 0)
    (h_ready : s.blockTimestamp >= s.storage pendingRegistryTimeSlot.slot) :
    ((activateRegistryChange).run s).snd.storageAddr registrySlot.slot =
      s.storageAddr pendingRegistrySlot.slot := by
  unfold activateRegistryChange onlyOwner
  simp [msgSender, getStorageAddr, getStorage, setStorageAddr, setStorage,
        registrySlot, pendingRegistrySlot, pendingRegistryTimeSlot,
        ownerSlot, require, bind, getBlockTimestamp,
        h_owner, h_pending, h_ready]

/-! ## Transfer is always blocked -/

theorem transfer_always_blocked
    (s : ContractState) (from to : Address) (amount : Uint256)
    (h_from_nonzero : from ≠ 0)
    (h_to_nonzero : to ≠ 0) :
    ((doTransfer from to amount).run s).fst.isRevert := by
  unfold doTransfer
  simp [require, bind, h_from_nonzero, h_to_nonzero]

/-! ## approve always reverts -/

theorem approve_always_reverts (s : ContractState) :
    ((approve).run s).fst.isRevert := by
  unfold approve
  simp [require, bind]

/-! ## permit always reverts -/

theorem permit_always_reverts (s : ContractState) :
    ((permit).run s).fst.isRevert := by
  unfold permit
  simp [require, bind]

/-! ## delegate only allows self-delegation -/

theorem delegate_allows_self (s : ContractState)
    (h_self : s.sender = s.sender) :
    ((delegateOp s.sender).run s).fst.isSuccess := by
  unfold delegateOp
  simp [msgSender, require, bind, pure, h_self]

theorem delegate_reverts_other
    (s : ContractState) (delegatee : Address)
    (h_other : delegatee ≠ s.sender) :
    ((delegateOp delegatee).run s).fst.isRevert := by
  unfold delegateOp
  simp [msgSender, require, bind, h_other]
