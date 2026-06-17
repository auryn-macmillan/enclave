import Lake
open Lake DSL

package "interfold-verity" where
  leanOptions := #[
    ⟨`pp.unicode.fun, true⟩,
    ⟨`autoImplicit, false⟩
  ]

require verity from git
  "https://github.com/lfglabs-dev/verity.git" @ "main"

@[default_target]
lean_lib «InterfoldVerity» where
  roots := #[
    -- Contract models (all compile)
    `InterfoldContracts.InterfoldToken.InterfoldToken,
    `InterfoldContracts.InterfoldTicketToken.InterfoldTicketToken,
    `InterfoldContracts.BondingRegistry.BondingRegistry,
    `InterfoldContracts.E3RefundManager.E3RefundManager,
    `InterfoldContracts.SlashingManager.SlashingManager,
    -- Specs (InterfoldToken only at this time)
    `InterfoldContracts.InterfoldToken.Spec
    -- Proofs deferred: Uint256 lacks LawfulBEq in Verity v4.22.0,
    -- blocking `require (value == 1)` guard proofs on Uint256-mapped data.
    -- Address-based comparisons (getStorageAddr) are unaffected.
  ]
