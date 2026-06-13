import Lake
open Lake DSL

-- This lakefile assumes the Verity repository is available as a dependency.
-- Set VERITY_ROOT environment variable or adjust the path below.

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
    `InterfoldToken.InterfoldToken,
    `InterfoldToken.Spec,
    `InterfoldToken.Invariants,
    `InterfoldToken.Proofs.Basic,
    `InterfoldTicketToken.InterfoldTicketToken,
    `InterfoldTicketToken.Spec,
    `InterfoldTicketToken.Invariants,
    `InterfoldTicketToken.Proofs.Basic,
    `BondingRegistry.BondingRegistry,
    `BondingRegistry.Spec,
    `BondingRegistry.Invariants,
    `BondingRegistry.Proofs.Basic,
    `E3RefundManager.E3RefundManager,
    `E3RefundManager.Spec,
    `E3RefundManager.Invariants,
    `E3RefundManager.Proofs.Basic,
    `SlashingManager.SlashingManager,
    `SlashingManager.Spec,
    `SlashingManager.Invariants,
    `SlashingManager.Proofs.Basic,
    `TrustBoundaries.Oracles,
    `TrustBoundaries.Assumptions
  ]
  globs := #[Glob.submodules `InterfoldToken,
             Glob.submodules `InterfoldTicketToken,
             Glob.submodules `BondingRegistry,
             Glob.submodules `E3RefundManager,
             Glob.submodules `SlashingManager,
             Glob.submodules `TrustBoundaries]
