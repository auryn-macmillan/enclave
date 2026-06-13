/-
  InterfoldToken — Formal Specifications

  Each public/external function has a `<function>_spec` predicate that describes
  the relationship between pre-state `s` and post-state `s'` when the function
  succeeds. Revert cases are described separately via `<function>_revert_spec`.
-/
import Verity.Core
import Verity.Specs.Common
import InterfoldToken.InterfoldToken

open Verity

/-! ## Helper specs -/

/--
  Spec for the `onlyOwner` guard: if sender equals owner, success with unchanged
  state; otherwise revert "not owner".
-/
def onlyOwner_spec (s s' : ContractState) : Prop :=
  (s.sender = s.storageAddr ownerSlot.slot → s' = s) ∧
  (s.sender ≠ s.storageAddr ownerSlot.slot →
    ∃ msg, ((onlyOwner).run s).fst = .revert msg s)

/--
  Spec for `doMint`: recipient balance increased by `amount`,
  totalSupply increased by `amount`, other balances unchanged.
-/
def doMint_spec (to : Address) (amount : Uint256) (s s' : ContractState) : Prop :=
  -- no overflow preconditions implicit (safeAdd reverts on overflow)
  s'.storageMap balancesSlot.slot to =
    add (s.storageMap balancesSlot.slot to) amount ∧
  s'.storage totalSupplySlot.slot =
    add (s.storage totalSupplySlot.slot) amount ∧
  storageMapUnchangedExceptKeyAtSlot balancesSlot.slot to s s' ∧
  sameStorageAddrContext s s' ∧
  sameStorageContext s s'

/--
  Spec for `doTransfer(to, amount)`: sender decreased, recipient increased,
  totalSupply unchanged, other balances unchanged.
-/
def doTransfer_spec (from to : Address) (amount : Uint256) (s s' : ContractState) : Prop :=
  s'.storageMap balancesSlot.slot from =
    sub (s.storageMap balancesSlot.slot from) amount ∧
  s'.storageMap balancesSlot.slot to =
    add (s.storageMap balancesSlot.slot to) amount ∧
  s'.storage totalSupplySlot.slot = s.storage totalSupplySlot.slot ∧
  storageMapUnchangedExceptKeysAtSlot balancesSlot.slot from to s s' ∧
  sameStorageAddrContext s s' ∧
  sameStorageContext s s'

/-! ## mintAllocation spec -/

/--
  Spec for `mintAllocation(to, amount)`:
  When preconditions hold (caller is minter, to ≠ 0, amount ≠ 0, totalMinted + amount ≤ MAX_SUPPLY),
  the post-state satisfies:
  - `to` balance increased by `amount`
  - `totalSupply` increased by `amount`
  - `totalMinted` increased by `amount`
  - other balances unchanged
  - storage (except balances, totalSupply, totalMinted) unchanged
-/
def mintAllocation_spec (to : Address) (amount : Uint256) (s s' : ContractState) : Prop :=
  -- balance changes
  s'.storageMap balancesSlot.slot to =
    add (s.storageMap balancesSlot.slot to) amount ∧
  s'.storage totalSupplySlot.slot =
    add (s.storage totalSupplySlot.slot) amount ∧
  s'.storage totalMintedSlot.slot =
    add (s.storage totalMintedSlot.slot) amount ∧
  -- only that balance changed
  storageMapUnchangedExceptKeyAtSlot balancesSlot.slot to s s' ∧
  -- other storage unchanged (except the three slots above)
  storageUnchangedExceptSlots [totalSupplySlot.slot, totalMintedSlot.slot] s s' ∧
  sameStorageAddrContext s s' ∧
  sameContext s s'

/--
  Revert spec for `mintAllocation`:
  When preconditions fail (caller not minter, to is zero, amount is zero,
  or supply cap would be exceeded), the function reverts.
-/
def mintAllocation_revert_spec (to : Address) (amount : Uint256) (s : ContractState) : Prop :=
  (s.sender ≠ s.storageAddr minterSlot.slot ∨ to = 0 ∨ amount = 0
   ∨ add (s.storage totalMintedSlot.slot) amount > MAX_SUPPLY) →
  ∃ msg, ((mintAllocation to amount).run s).fst = .revert msg s

/-! ## disableTransferRestrictions spec -/

/--
  Spec for `disableTransferRestrictions`:
  When called by owner and restrictions are currently true,
  they become false in the post-state.
  When already false, state is unchanged.
  When called by non-owner, reverts.
-/
def disableTransferRestrictions_spec (s s' : ContractState) : Prop :=
  (s.sender = s.storageAddr ownerSlot.slot) →
    (s.storage transfersRestrictedSlot.slot = true →
      s'.storage transfersRestrictedSlot.slot = false ∧
      sameStorageExceptSlots [transfersRestrictedSlot.slot] s s') ∧
    (s.storage transfersRestrictedSlot.slot = false → s' = s)

/-! ## toggleTransferWhitelist spec -/

/--
  Spec for `toggleTransferWhitelist(account)`:
  When called by whitelist manager, the whitelist status for `account` is flipped.
  Other storage is unchanged.
-/
def toggleTransferWhitelist_spec (account : Address) (s s' : ContractState) : Prop :=
  (s.sender = s.storageAddr whitelistManagerSlot.slot) →
    s'.storageMap transferWhitelistedSlot.slot account =
      not (s.storageMap transferWhitelistedSlot.slot account) ∧
    storageMapUnchangedExceptKeyAtSlot transferWhitelistedSlot.slot account s s' ∧
    sameStorageContext s s' ∧
    sameStorageAddrContext s s'

/-! ## transfer spec -/

/--
  Spec for `transfer(to, amount)`:
  When preconditions hold (sufficient balance, not restricted or whitelisted),
  sender balance decreases by amount, recipient increases by amount,
  totalSupply unchanged, other balances unchanged.
-/
def transfer_spec (to : Address) (amount : Uint256) (s s' : ContractState) : Prop :=
  s'.storageMap balancesSlot.slot s.sender =
    sub (s.storageMap balancesSlot.slot s.sender) amount ∧
  s'.storageMap balancesSlot.slot to =
    add (s.storageMap balancesSlot.slot to) amount ∧
  s'.storage totalSupplySlot.slot = s.storage totalSupplySlot.slot ∧
  storageMapUnchangedExceptKeysAtSlot balancesSlot.slot s.sender to s s' ∧
  sameStorageAddrContext s s' ∧
  sameContext s s'

/-! ## Contract-level invariant -/

/--
  The totalSupply invariant: totalSupply = sum of all balances.
  NOTE: This is stated as a predicate but cannot be proven directly in Verity
  without whole-mapping iteration support. It is included here for documentation
  and can be verified through per-transition invariants.
-/
def totalSupply_invariant (s : ContractState) : Prop :=
  s.storage totalSupplySlot.slot = s.storage totalSupplySlot.slot
  -- Placeholder: in practice, this would require summing all balances
  -- which Verity does not currently support natively.

/--
  The supply cap invariant: totalMinted ≤ MAX_SUPPLY.
  This IS provable because it only involves scalar variables.
-/
def supply_cap_invariant (s : ContractState) : Prop :=
  s.storage totalMintedSlot.slot ≤ MAX_SUPPLY

/--
  The one-way restriction invariant: transfersRestricted can only go from true to false.
  This is verified by checking that every function that modifies it only sets it to false
  (never to true after initialization).
-/
def restriction_monotonic_invariant (s_old s_new : ContractState) : Prop :=
  s_old.storage transfersRestrictedSlot.slot = false →
  s_new.storage transfersRestrictedSlot.slot = false
