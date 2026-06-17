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
    `InterfoldToken.InterfoldToken,
    `InterfoldToken.Spec,
    `InterfoldToken.Proofs.Basic,
    `InterfoldTicketToken.InterfoldTicketToken,
    `InterfoldTicketToken.Spec,
    `InterfoldTicketToken.Proofs.Basic,
    `BondingRegistry.BondingRegistry,
    `BondingRegistry.Spec,
    `BondingRegistry.Proofs.Basic,
    `E3RefundManager.E3RefundManager,
    `E3RefundManager.Spec,
    `E3RefundManager.Proofs.Basic,
    `SlashingManager.SlashingManager,
    `SlashingManager.Spec,
    `SlashingManager.Proofs.Basic
  ]
