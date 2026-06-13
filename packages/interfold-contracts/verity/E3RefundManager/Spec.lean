/-
  E3RefundManager — Formal Specifications
-/
import Verity.Core
import Verity.Specs.Common
import E3RefundManager.E3RefundManager

open Verity

/--
  Work allocation BPS bound: the sum of all BPS values must be ≤ 10000 (100%).
  This is a critical invariant that must be enforced by `setWorkAllocation`.
-/
def work_allocation_bound (s : ContractState) : Prop :=
  let cf := s.storage committeeFormationBpsSlot.slot
  let dkg := s.storage dkgBpsSlot.slot
  let dec := s.storage decryptionBpsSlot.slot
  let prot := s.storage protocolBpsSlot.slot
  let ssb := s.storage successSlashedNodeBpsSlot.slot
  add (add (add (add cf dkg) dec) prot) ssb ≤ 10000

/--
  Claim replay protection: each (e3Id, claimant) pair can only claim once.
-/
def claim_replay_protection (e3Id : Uint256) (claimant : Address) (s s' : ContractState) : Prop :=
  s.storageMap2 claimedSlot.slot e3Id claimant = true →
  s'.storageMap2 claimedSlot.slot e3Id claimant = true
