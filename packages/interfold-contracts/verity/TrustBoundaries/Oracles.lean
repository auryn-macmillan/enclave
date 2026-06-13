/-
  TrustBoundaries — Oracle Declarations

  External contract calls and cryptographic primitives that reside on
  trust boundaries in our Verity models. Each oracle is documented with
  the Solidity call it mirrors and the assumed pre/post condition.
-/
import Verity.Core

open Verity

/-!
  ## Cross-Contract Oracle Boundaries

  These represent calls to other Interfold contracts that are not modeled
  within the current Verity contract's proof. The callee's behavior is
  assumed correct based on the Solidity implementation.

  ---
  ### `oracle_ciphernodeRegistry_addCiphernode(node)`
  **Solidity**: `CiphernodeRegistryOwnable.addCiphernode(msg.sender)`
  **Caller**: BondingRegistry.registerOperator()
  **Assumption**: Adds the node to the ciphernode IMT and emits `CiphernodeAdded`.
  **Pre**: `node` is a valid address, not already in the IMT.
  **Post**: Node is registered in the ciphernode registry.

  ### `oracle_ciphernodeRegistry_removeCiphernode(node)`
  **Solidity**: `CiphernodeRegistryOwnable.removeCiphernode(msg.sender)`
  **Caller**: BondingRegistry.deregisterOperator()
  **Assumption**: Removes the node from the IMT, zeroing its slot.
  **Pre**: `node` is registered in the registry.
  **Post**: Node is removed from the IMT.

  ### `oracle_slashingManager_isBanned(node) → bool`
  **Solidity**: `SlashingManager.isBanned(node)`
  **Caller**: BondingRegistry.registerOperator()
  **Assumption**: Returns true if the node has been banned.
  **Pre**: None.
  **Post**: Returns current ban status.

  ### `oracle_slashingManager_hasOpenLaneBProposal(node) → bool`
  **Solidity**: `SlashingManager.hasOpenLaneBProposal(node)`
  **Caller**: BondingRegistry.deregisterOperator()
  **Assumption**: Returns true if the operator has an unresolved Lane B slash.
  **Pre**: None.
  **Post**: Returns true iff the operator has a pending Lane B proposal.

  ---
  ## ERC20 Token Oracle Boundaries

  ### `oracle_ticketToken_depositFrom(from, to, amount)`
  **Solidity**: `InterfoldTicketToken.depositFrom(from, to, amount)`
  **Caller**: BondingRegistry.addTicketBalance()
  **Assumption**: Mints `amount` ITK to `to`, transferring `amount` underlying from `from`.
  **Pre**: `from` has approved sufficient underlying allowance.
  **Post**: `to`'s ITK balance increased by `amount`, underlying transferred.

  ### `oracle_ticketToken_burnTickets(op, amount)`
  **Solidity**: `InterfoldTicketToken.burnTickets(op, amount)`
  **Caller**: BondingRegistry (slashing)
  **Assumption**: Burns `amount` ITK from `op`, incrementing payableBalance.
  **Pre**: `op` has >= `amount` ITK balance.
  **Post**: `op`'s ITK balance decreased, payableBalance increased.

  ### `oracle_licenseToken_safeTransferFrom(from, to, amount)`
  **Solidity**: `SafeERC20.safeTransferFrom(IERC20(licenseToken), from, address(this), amount)`
  **Caller**: BondingRegistry.bondLicense()
  **Assumption**: Transfers `amount` INTF from `from` to the BondingRegistry.
  **Pre**: `from` has approved sufficient INTF allowance.
  **Post**: BondingRegistry's INTF balance increased by `amount`.

  ---
  ## Cryptographic Oracle Boundaries

  ### `oracle_keccak256(data) → bytes32`
  **Solidity**: `keccak256(data)`
  **Used by**: SlashingManager (evidence hashing), CiphernodeRegistry (score, IMT)
  **Assumption**: Standard keccak256 hash function behavior.
  **Status**: Axiomatized in Verity. Use `--deny-axiomatized-primitives` to enforce exclusion.

  ### `oracle_ecdsa_recover(hash, signature) → address`
  **Solidity**: `ECDSA.recover(hash, signature)`
  **Used by**: SlashingManager (attestation vote verification)
  **Assumption**: Standard ECDSA recovery behavior. Returns the signer address.
  **Status**: Precompile trust boundary. Modeled as `ecrecover` ECM.

  ---
  ## ZK Verifier Oracle Boundaries

  ### `oracle_bfvPkVerifier_verify(proof, publicInputs) → bool`
  **Solidity**: `BfvPkVerifier.verify(proof, publicInputs)`
  **Used by**: Interfold (C5 pk aggregation verification)
  **Assumption**: Returns true iff the proof is valid for the given public inputs.
  **Status**: Outside proof envelope. ZK circuit correctness is a separate audit surface.

  ### `oracle_bfvDecryptionVerifier_verify(proof, publicInputs) → bool`
  **Solidity**: `BfvDecryptionVerifier.verify(proof, publicInputs)`
  **Used by**: Interfold (C7 decryption verification)
  **Assumption**: Returns true iff the decryption proof is valid.
  **Status**: Outside proof envelope.
-/
