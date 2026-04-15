<div align="center">
  <picture>
    <img src="./interfold-meta.jpg" alt="The Interfold" width="100%">
  </picture>

[![Docs][docs-badge]][docs] [![Github Actions][gha-badge]][gha] [![Hardhat][hardhat-badge]][hardhat]
[![License: LGPL v3][license-badge]][license]

</div>

# The Interfold

> **Note:** The Interfold was previously known as **Enclave**.  
> Many repositories, packages, and CLI tools still use the `enclave` name while the project
> transitions.

This is the monorepo for **The Interfold**, an open-source protocol for confidential coordination.

The Interfold leverages a combination of Fully Homo morphic Encryption (FHE), Zero-Knowledge Proofs (ZKPs), and Multi-Party Computation (MPC) to enable Encrypted Execution Environments (E3), with integrity and privacy guarantees rooted in cryptography and economics, rather than hardware and attestations.

## Auction Bit-Plane Demo

This example now demonstrates a sealed-bid **discrete-ladder Vickrey auction** using threshold BFV. Bids are mapped onto a public price ladder, aggregated into cumulative occupancy and pair-indicator curves, and only the minimum authorized decryptions needed for the second price and winner are made public.

### How to Run the Demo

#### 1. Build the project
```bash
cd examples/auction-bitplane
cargo build --release
```

#### 2. Run the demo
```bash
cargo run --bin demo --release
```

The demo prints:
- the public ladder bids submitted by each participant,
- the decrypted aggregate occupancy curve,
- the second-price bucket,
- the minimal extra winner-identification reveal,
- and a plaintext shadow verification.

## Documentation

Full documentation is available at: https://docs.theinterfold.com

## Getting Help

Join the community [Telegram group][telegram].

## Contributing

See [CONTRIBUTING.md][contributing].

## Development

This section covers the essential commands for setting up and working with the Enclave codebase locally.

```bash
# Install dependencies
pnpm i

# Build the project
pnpm build

# Clean build artifacts
pnpm clean
```

### Testing

**⚠️ Important:** Always run tests through pnpm scripts, not directly via `cargo test` or other build tools.

#### Test Scripts

- **`pnpm test`** - Runs all tests across the entire monorepo.
- **`pnpm rust:test`** - Runs all Rust crate tests in the `crates/` directory.
- **`pnpm evm:test`** - Runs tests for the EVM smart contracts.
- **`pnpm sdk:test`** - Runs tests for the TypeScript SDK.
- **`pnpm noir:test`** - Runs tests for Noir circuits.
- **`pnpm test:integration`** - Runs integration tests.

### Contributors

<!-- readme: contributors -start -->
<table>
	<tbody>
		<tr>
            <td align="center">
                <a href="https://github.com/ryardley">
                    <img src="https://avatars.githubusercontent.com/u/1256409?v=4" width="100;" alt="ryardley"/>
                    <br />
                    <sub><b>гλ</b></sub>
                </a>
            </td>
            <td align="center">
                <a href="https://github.com/auryn-macmillan">
                    <img src="https://avatars.githubusercontent.com/u/8453294?v=4" width="100;" alt="auryn-macmillan"/>
                    <br />
                    <sub><b>Auryn Macmillan</b></sub>
                </a>
            </td>
            <td align="center">
                <a href="https://github.com/hmzakhalid">
                    <img src="https://avatars.githubusercontent.com/u/36852564?v=4" width="100;" alt="hmzakhalid"/>
                    <br />
                    <sub><b>Hamza Khalid</b></sub>
                </a>
            </td>
            <td align="center">
                <a href="https://github.com/samepant">
                    <img src="https://avatars.githubusercontent.com/u/6718506?v=4" width="100;" alt="samepant"/>
                    <br />
                    <sub><b>samepant</b></sub>
                </a>
            </td>
            <td align="center">
                <a href="https://github.com/ctrlc03">
                    <img src="https://avatars.githubusercontent.com/u/93448202?v=4" width="100;" alt="ctrlc03"/>
                    <br />
                    <sub><b>ctrlc03</b></sub>
                </a>
            </td>
            <td align="center">
                <a href="https://github.com/cristovaoth">
                    <img src="https://avatars.githubusercontent.com/u/12870300?v=4" width="100;" alt="cristovaoth"/>
                    <br />
                    <sub><b>Cristóvão</b></sub>
                </a>
            </td>
		</tr>
	</tbody>
</table>
<!-- readme: contributors-end -->

## Minimum Rust version

This workspace's minimum supported rustc version is 1.86.0.

## Architecture

The Interfold employs a modular architecture involving numerous actors and participants.

## 🚀 Release Process

### Overview

The Interfold uses a unified versioning strategy where all packages share the same version number. Releases are triggered by git tags and follow semantic versioning.

## 🏷️ Version Strategy

### Version Format

The Interfold follows [Semantic Versioning](https://semver.org/):

- **Stable**: `v1.0.0` - Production ready
- **Pre-release**: `v1.0.0-beta.1` - Testing/preview versions

## 🌿 Branch and Tag Strategy

- **`main`** - Latest code. All releases are tagged from here.

## 📋 Release Checklist

For maintainers doing a release:

- [ ] Ensure all tests pass on `main`
- [ ] Review commits since last release
- [ ] Decide version number
- [ ] Run `pnpm bump:versions X.Y.Z`
- [ ] Monitor GitHub Actions

## 🔧 Script Options

The `bump:versions` script supports several options:

```bash
# Full automatic release (default)
pnpm bump:versions 1.0.0

# Local only - don't push
pnpm bump:versions --no-push 1.0.0

# Skip git operations entirely
pnpm bump:versions --skip-git 1.0.0

# Dry run - see what would happen
pnpm bump:versions --dry-run 1.0.0
```

## 🔄 Rollback Procedure

If a release has issues:

1. **Mark as deprecated on npm**
2. **Yank from crates.io**
3. **Fix and release patch**

## 📊 Version History

Check our [Releases page](https://github.com/gnosisguild/enclave/releases) for full version history and changelogs.

## Security and Liability

This repo is provided WITHOUT ANY WARRANTY.

## License

This repo created under the [LGPL-3.0+ license](LICENSE).

[gha]: https://github.com/gnosisguild/enclave/actions
[gha-badge]: https://github.com/gnosisguild/enclave/actions/workflows/ci.yml/badge.svg
[hardhat]: https://hardhat.org/
[hardhat-badge]: https://img.shields.io/badge/Built%20with%20Hardhat-FFDB1C.svg
[license]: https://opensource.org/license/lgpl-3-0
[license-badge]: https://img.shields.io/badge/License-LGPLv3.0-blue.svg
[docs]: https://docs.theinterfold.com
[docs-badge]: https://img.shields.io/badge/Documentation-blue.svg
[quick-start]: https://docs.theinterfold.com/quick-start
[crisp]: https://docs.theinterfold.com/CRISP/introduction
[telegram]: https://t.me/+raYAZgrwgOw2ODJh
[contributing]: CONTRIBUTING.md
