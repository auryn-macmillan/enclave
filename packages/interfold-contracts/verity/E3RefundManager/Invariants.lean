/-
  E3RefundManager — Contract Invariants

  Pull-payment accounting invariants.
-/
import Verity.Core
import E3RefundManager.E3RefundManager

open Verity

/--
  **Distribution idempotency**: Once an E3's refund distribution is calculated,
  it cannot be recalculated. Enforced by the `calculated` flag.
-/
def inv_distribution_idempotent (e3Id : Uint256) (s : ContractState) : Prop :=
  s.storageMap distributionsCalculatedSlot.slot e3Id = true

/--
  **Claim replay protection**: Each (e3Id, claimant) can claim at most once.
  Enforced by the `claimed` mapping.
-/
def inv_claim_replay (e3Id : Uint256) (claimant : Address) (s : ContractState) : Prop :=
  s.storageMap2 claimedSlot.slot e3Id claimant = false

/--
  **Pending slashed funds non-negative**: Accumulated slashed funds for any E3
  are always ≥ 0 (trivially true for Uint256).
-/
def inv_slashed_funds_nonnegative (e3Id : Uint256) (s : ContractState) : Prop := True
