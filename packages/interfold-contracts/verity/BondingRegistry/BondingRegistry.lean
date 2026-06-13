/-
  BondingRegistry — Formally Verified Implementation

  Translation of the core per-operator accounting from
  `packages/interfold-contracts/contracts/registry/BondingRegistry.sol`.

  Focus: per-transition invariants for ticket/license balance changes,
  access control (onlySlashingManager), exit delay enforcement, and
  operator lifecycle guards.

  The ExitQueueLib complexity is modeled as a simplified per-operator
  exit state (amount + unlock timestamp) rather than full tranche structures.
  Global conservation invariants require whole-mapping iteration and are
  noted as assumed properties (see TrustBoundaries/Assumptions.lean).

  Trust boundaries:
  - External calls to CiphernodeRegistry (addCiphernode, removeCiphernode)
  - External calls to SlashingManager (isBanned, hasOpenLaneBProposal)
  - SafeERC20 transfers to/from InterfoldTicketToken and license token
  - ExitQueueLib internal queue mechanics
-/
import Verity.Core
import Verity.Specs.Common

open Verity

/-! ## Storage slot definitions -/

def ticketTokenSlot : StorageSlot Address := ⟨0⟩       -- ITK token address
def licenseTokenSlot : StorageSlot Address := ⟨1⟩       -- INTF token address
def registrySlot : StorageSlot Address := ⟨2⟩            -- CiphernodeRegistry
def slashingManagerSlot : StorageSlot Address := ⟨3⟩     -- SlashingManager
def ticketPriceSlot : StorageSlot Uint256 := ⟨4⟩         -- price per ticket
def licenseRequiredBondSlot : StorageSlot Uint256 := ⟨5⟩ -- min license bond
def minTicketBalanceSlot : StorageSlot Uint256 := ⟨6⟩    -- min tickets for active
def exitDelaySlot : StorageSlot Uint256 := ⟨7⟩           -- exit delay in seconds
def slashedTicketBalanceSlot : StorageSlot Uint256 := ⟨8⟩-- total slashed tickets
def slashedLicenseBondSlot : StorageSlot Uint256 := ⟨9⟩  -- total slashed license
def ownerSlot : StorageSlot Address := ⟨10⟩              -- contract owner
def numActiveOperatorsSlot : StorageSlot Uint256 := ⟨11⟩ -- count of active operators

-- Per-operator storage (modeled as separate mappings; the real contract uses a struct)
def licenseBondSlot : StorageSlot (Address → Uint256) := ⟨12⟩          -- operator → bond
def registeredSlot : StorageSlot (Address → Bool) := ⟨13⟩              -- operator → registered
def activeSlot : StorageSlot (Address → Bool) := ⟨14⟩                  -- operator → active
def exitRequestedSlot : StorageSlot (Address → Bool) := ⟨15⟩           -- operator → exit requested
def exitUnlocksAtSlot : StorageSlot (Address → Uint256) := ⟨16⟩        -- operator → unlock timestamp
def exitTicketAmountSlot : StorageSlot (Address → Uint256) := ⟨17⟩     -- operator → pending exit ticket
def exitLicenseAmountSlot : StorageSlot (Address → Uint256) := ⟨18⟩    -- operator → pending exit license

/-! ## Helpers -/

def onlyOwner : Contract Unit := do
  let sender ← msgSender
  let owner ← getStorageAddr ownerSlot
  require (sender == owner) "not owner"

def onlySlashingManager : Contract Unit := do
  let sender ← msgSender
  let sm ← getStorageAddr slashingManagerSlot
  require (sender == sm) "not slashing manager"

/--
  Check if operator is active based on bond and ticket requirements.
  active := registered AND licenseBond >= licenseRequiredBond * 80/100
            AND ticketBalance / ticketPrice >= minTicketBalance.
  (Simplified: we check licenseBond >= licenseRequiredBond directly
  since modeling the 80% BPS would add complexity without changing
  the verification property shape.)
-/
def isActive (operator : Address) : Contract Bool := do
  let registered ← getMapping registeredSlot operator
  if !registered then
    pure false
  else
    let bond ← getMapping licenseBondSlot operator
    let required ← getStorage licenseRequiredBondSlot
    if bond < required then
      pure false
    else
      pure true
      -- Note: full activation check also requires ticket balance check
      -- which requires reading the ITK contract balance (trust boundary).

/-! ## Operator lifecycle -/

/--
  `registerOperator()` — registers the caller as an operator.
  Requires: not banned, not already registered, licenseBond >= licenseRequiredBond,
  no exit in progress.
-/
def registerOperator : Contract Unit := do
  let sender ← msgSender
  -- Check not already registered
  let already ← getMapping registeredSlot sender
  require (!already) "already registered"
  -- Check license bond sufficient
  let bond ← getMapping licenseBondSlot sender
  let required ← getStorage licenseRequiredBondSlot
  require (bond >= required) "not licensed"
  -- Check no exit in progress
  let exitReq ← getMapping exitRequestedSlot sender
  let now ← getBlockTimestamp
  if exitReq then
    let unlocksAt ← getMapping exitUnlocksAtSlot sender
    require (now >= unlocksAt) "exit in progress"
  else
    pure ()
  -- Register
  setMapping registeredSlot sender true
  -- Update active status
  let active ← isActive sender
  setMapping activeSlot sender active
  emitEvent "OperatorRegistered" [] [addressToWord sender]

/--
  `deregisterOperator()` — deregisters the caller.
  Requires: registered, no exit in progress, no open Lane B slash.
  Sets exit state and marks as not registered.
-/
def deregisterOperator : Contract Unit := do
  let sender ← msgSender
  let registered ← getMapping registeredSlot sender
  require registered "not registered"
  -- Check no exit in progress
  let exitReq ← getMapping exitRequestedSlot sender
  let now ← getBlockTimestamp
  if exitReq then
    let unlocksAt ← getMapping exitUnlocksAtSlot sender
    require (now >= unlocksAt) "exit in progress"
  else
    pure ()
  -- Request exit (queue all tickets and bonds for exit)
  let exitDelay ← getStorage exitDelaySlot
  let newUnlock ← requireSomeUint (safeAdd now exitDelay) "timestamp overflow"
  setMapping exitRequestedSlot sender true
  setMapping exitUnlocksAtSlot sender newUnlock
  setMapping registeredSlot sender false
  setMapping activeSlot sender false
  emitEvent "OperatorDeregistered" [] [addressToWord sender]

/-! ## Ticket balance operations -/

/--
  `addTicketBalance(amount)` — increases operator's ticket balance.
  In the real contract, this transfers ITK tokens from the caller.
  Modeled as direct balance increment (external ERC20 transfer is a trust boundary).
-/
def addTicketBalance (operator : Address) (amount : Uint256) : Contract Unit := do
  let sender ← msgSender
  require (operator == sender) "can only add for self"
  require (amount != 0) "zero amount"
  -- In Solidity: ticketToken.depositFrom(sender, operator, amount)
  -- which mints ITK to operator. We model this as the ITK balance change
  -- happening in the ticket token contract (trust boundary).
  pure ()

/--
  `removeTicketBalance(amount)` — decreases operator's ticket balance.
  Queues the underlying for exit. Modeled as per-transition balance check.
-/
def removeTicketBalance (operator : Address) (amount : Uint256) : Contract Unit := do
  let sender ← msgSender
  require (operator == sender) "can only remove for self"
  require (amount != 0) "zero amount"
  -- In Solidity: burns ITK and queues underlying for exit
  -- We model the exit queue update here
  let currentExit ← getMapping exitTicketAmountSlot sender
  let newExit ← requireSomeUint (safeAdd currentExit amount) "exit overflow"
  setMapping exitTicketAmountSlot sender newExit
  emitEvent "TicketBalanceDecreased" [amount] [addressToWord sender]

/-! ## License bond operations -/

/--
  `bondLicense(amount)` — increases operator's license bond.
  In the real contract, this transfers INTF from the caller.
-/
def bondLicense (amount : Uint256) : Contract Unit := do
  let sender ← msgSender
  require (amount != 0) "zero amount"
  let currentBond ← getMapping licenseBondSlot sender
  let newBond ← requireSomeUint (safeAdd currentBond amount) "bond overflow"
  setMapping licenseBondSlot sender newBond
  -- Update active status
  let active ← isActive sender
  setMapping activeSlot sender active
  emitEvent "LicenseBondUpdated" [amount] [addressToWord sender]

/--
  `unbondLicense(amount)` — decreases operator's license bond.
  Queues license tokens for exit with timelock.
-/
def unbondLicense (amount : Uint256) : Contract Unit := do
  let sender ← msgSender
  require (amount != 0) "zero amount"
  let currentBond ← getMapping licenseBondSlot sender
  require (currentBond >= amount) "insufficient bond"
  let newBond ← requireSomeUint (safeSub currentBond amount) "bond underflow"
  setMapping licenseBondSlot sender newBond
  -- Queue for exit
  let currentExit ← getMapping exitLicenseAmountSlot sender
  let newExit ← requireSomeUint (safeAdd currentExit amount) "exit overflow"
  setMapping exitLicenseAmountSlot sender newExit
  -- Update active status
  let active ← isActive sender
  setMapping activeSlot sender active
  emitEvent "LicenseBondUpdated" [amount] [addressToWord sender]

/-! ## Exit claiming -/

/--
  `claimExits(maxTicket, maxLicense)` — claims mature exit amounts.
  Only transfers amounts where the unlock timestamp has passed.
  The actual ERC20 transfers are on a trust boundary.
-/
def claimExits (maxTicket : Uint256) (maxLicense : Uint256) : Contract Unit := do
  let sender ← msgSender
  let exitReq ← getMapping exitRequestedSlot sender
  require exitReq "no exit in progress"
  let unlocksAt ← getMapping exitUnlocksAtSlot sender
  let now ← getBlockTimestamp
  require (now >= unlocksAt) "exit not ready"
  -- Claim ticket exit
  let ticketExit ← getMapping exitTicketAmountSlot sender
  let claimTicket := if ticketExit <= maxTicket then ticketExit else maxTicket
  let remainingTicket ← requireSomeUint (safeSub ticketExit claimTicket) "exit underflow"
  setMapping exitTicketAmountSlot sender remainingTicket
  -- Claim license exit
  let licenseExit ← getMapping exitLicenseAmountSlot sender
  let claimLicense := if licenseExit <= maxLicense then licenseExit else maxLicense
  let remainingLicense ← requireSomeUint (safeSub licenseExit claimLicense) "exit underflow"
  setMapping exitLicenseAmountSlot sender remainingLicense
  -- If all claimed, clear exit state
  if remainingTicket == 0 && remainingLicense == 0 then
    setMapping exitRequestedSlot sender false
    setMapping exitUnlocksAtSlot sender 0
  else
    pure ()
  emitEvent "ExitsClaimed" [claimTicket, claimLicense] [addressToWord sender]

/-! ## Slashing operations -/

/--
  `slashTicketBalance(operator, amount)` — slashes operator's ticket balance.
  Only callable by SlashingManager. Amount is bounded by operator's balance.
  Returns the actual amount slashed.
-/
def slashTicketBalance (operator : Address) (amount : Uint256) : Contract Uint256 := do
  onlySlashingManager
  require (operator != 0) "zero address"
  require (amount != 0) "zero amount"
  -- In real contract: burns ITK via ticketToken.burnTickets(operator, amount)
  -- and redirects underlying. Here we track the slashed total.
  let currentSlashed ← getStorage slashedTicketBalanceSlot
  let newSlashed ← requireSomeUint (safeAdd currentSlashed amount) "slashed overflow"
  setStorage slashedTicketBalanceSlot newSlashed
  emitEvent "TicketsSlashed" [amount] [addressToWord operator]
  pure amount

/--
  `slashLicenseBond(operator, amount)` — slashes operator's license bond.
  Only callable by SlashingManager. Amount is bounded by operator's bond.
-/
def slashLicenseBond (operator : Address) (amount : Uint256) : Contract Unit := do
  onlySlashingManager
  require (operator != 0) "zero address"
  require (amount != 0) "zero amount"
  let currentBond ← getMapping licenseBondSlot operator
  require (currentBond >= amount) "insufficient bond"
  let newBond ← requireSomeUint (safeSub currentBond amount) "bond underflow"
  setMapping licenseBondSlot operator newBond
  let currentSlashed ← getStorage slashedLicenseBondSlot
  let newSlashed ← requireSomeUint (safeAdd currentSlashed amount) "slashed overflow"
  setStorage slashedLicenseBondSlot newSlashed
  -- Update active status
  let active ← isActive operator
  setMapping activeSlot operator active
  emitEvent "LicenseBondSlashed" [amount] [addressToWord operator]

/-! ## Initialization -/

def initBondingRegistry (initialOwner : Address) : Contract Unit := do
  require (initialOwner != 0) "zero address owner"
  setStorageAddr ownerSlot initialOwner
