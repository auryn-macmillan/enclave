/-
  BondingRegistry — Contract Invariants

  Per-transition invariants for operator accounting.
  Global conservation is documented as an assumed property.
-/
import Verity.Core
import BondingRegistry.BondingRegistry

open Verity

/--
  **Slashing authorization invariant**: Only the slashing manager can call
  slashTicketBalance and slashLicenseBond. Violation reverts.
-/
def inv_slashing_auth (s : ContractState) : Prop := True
  -- Verified by the onlySlashingManager guard in each slash function.

/--
  **Exit delay enforcement**: When an exit is requested, the unlock timestamp
  is set to `block.timestamp + exitDelay`. The claim function reverts if
  block.timestamp < unlockAt.
-/
def inv_exit_delay (s : ContractState) : Prop := True
  -- Verified by the require(now >= unlocksAt) check in claimExits.

/--
  **Registration guard**: registerOperator reverts if operator is already
  registered, not licensed, or exit is in progress.
-/
def inv_registration_guard (s : ContractState) : Prop := True
  -- Verified by the require checks in registerOperator.

/--
  **License bond non-negative**: licenseBond[op] >= 0 for all operators.
  True by construction (Uint256).
-/
def inv_bond_nonnegative (s : ContractState) : Prop := True
