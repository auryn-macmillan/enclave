# r140 consumer-pin source-check (2026-09-27)

One analytic round that RAN-verifies a load-bearing design premise for the
owner-gated r140 in-tree C4 consumer diff (persistent line: "consumer
S-sponge DELETE + acc-pin ADD, per-(h,l) cell 2,732-g-class; diff base
62cc527f"). No circuits/ or crates/ source edit; no nargo/bb/cargo
(only python3 big ints + git fetch + nproc/free). Design-side work under
the 2026-09-12 owner sign-off, which gates only circuit/crates source
diffs per-diff - this round makes none.

## Claim

The r140 consumer shape swaps the C4 consumer's collision-resistant
SAFE sponge for a single strided acc-pin per (h,l) cell. The r136 design
notes cite safety as "safe only WITH co-enforced per-coeff range+parity
pins" - but those co-pins live in the C2 PRODUCER module, not the C4
consumer. Is the r140 spec therefore kernel-closed at the consumer?
This round reads the in-tree consumer + producer modules and RAN-computes
the answer.

## Method (all RAN, in-list files only)

1. Grep the in-tree C4 consumer module
   circuits/lib/src/core/dkg/share_decryption.nr for range_check,
   check_range_bounds, parity, and the acc-pin stride constant
   3641542188856621199 -> 0 hits in all four.
2. Read the module in full: verify_commitments (L53-71) is the only
   per-cell binding the consumer applies to its own witness; it is a
   SAFE-sponge commitment assertion. No consumer-side coefficient
   range pin, parity pin, or acc pin exists in-tree.
3. Grep the C2 producer module circuits/lib/src/core/dkg/
   share_computation.nr: range-check family present
   (L102/L172/L245-257), parity check present, same acc stride
   as the r137 consumer probe.
4. Extract the secure-8192 limb modulus upper bound Q from
   fhe-params/src/constants.rs MODULI Sec8192 (L45-49):
   Q = 0x2000000015a0001 (58-bit). N=8192, P = BN254 (255-bit,
   value matched against the on-disk r136 probe).
5. Run the in-box visits probe (poc/r140_gate_source_check/visits.py)
   which re-derives three claims at the in-tree numbers:
   - K: pin(k)=0 on the r136 kernel vector, and in-box? (no - that
     vector's coordinate is 255-bit but the per-coord box is 58-bit)
   - V: lower bound on in-box witness vectors per acc value, given the
     real in-box per-coord bound [0, Q)^N and P-bit output
   - D: the actual r136 kernel coordinate and its gap vs the box.

## RAN results (verbatim poc/r140_gate_source_check/RAN.out)

- K: pin(k) = 0 (r136 kernel identity re-confirmed at the in-tree A, P)
- K: in_box = False; kernel vector's max coord is 255-bit, box is 58-bit
- V: in-box witness fiber lower bound = 2^474,881
  (secret entropy ceiling N*bits(Q) = 475,136 bits, minus 255-bit output)
- D: kernel coordinate (P-A) mod P is 255 bits, i.e. ~197 bits beyond
  the per-coord box [0, 2^58); the coord exceeds Q by a multiplier of
  0x39f6d3a96da2f17d9f1bfa1b4ed2452ea79dab998f9709b4d1

## Findings / verdict

1. RAN: the in-tree C4 consumer has ZERO per-coeff range, parity, or
   acc pins. The co-pin family cited in r136 design notes exists only in
   the C2 producer module (range check, parity check, and the safe-sponge
   commitment are applied at production, not verification).

2. RAN: the r136 kernel vector is OUT of the per-coeff box
   (255-bit coord vs a 58-bit box). The "safe only with co-enforced
   range+parity pins" argument was never tested at the in-box consumer
   shape - the r136 kernel vector itself is a valid example of this: it
   is a kernel vector in the wild, not in C4-consumer's box.

3. RAN: even restricted to in-box witnesses [0, 2^58)^8192, a single
   per-cell acc-pin (one P-bit output over 8192 limb positions x 58-bit
   slots) has an in-box fiber of at least 2^474,881 distinct witness
   vectors. Acc-pin + per-coeff range pin together do NOT close the
   kernel at the consumer; the r140 persistent-line spec as literally
   stated (sponge DELETE + acc-pin ADD, 2,732 g/cell) is not
   kernel-closed on the consumer witness set.

4. DRAFT (cost-class needed to close it): to close, the r140 diff must
   also ADD at the consumer the C2-consumer-side range pins + parity
   check, mirroring the producer family. The per-cell cost of that
   additional gate class is unmeasured this round (would need an r137-
   class K-cell nargo probe at the enhanced shape - record as next
   DRAFT for the owner's re-gate, not for this in-list round).

## Consequence for r140 (owner-gated; nothing landed)

The owner re-gate of the r140 in-tree C4 consumer diff should be
re-shaped from the persistent-line "acc-pin ADD only" formatting to:
S-sponge DELETE + acc-pin ADD + per-coeff range-pin ADD + parity-check
ADD at the C4 consumer (mirroring the C2 producer co-pin family), or
verify some other closure argument (e.g., the producer's safe sponge
already binds each share at production and the consumer re-binding is
redundant - which is a stronger claim to make, but that needs the
SHAPE of the consumer puzzle: does the consumer's decrypted_shares
witness come from the producer's span/index/keyflow binding such that
each coordinate is already INDIVIDUALLY bound?). This is a design-open
question for the owner, not something this in-list round settles.

## What this round did NOT do (negative evidence)

- No code or environment changes. No circuit/ or crates/ edit (the
    2026-09-12 sign-off, per-diff owner re-gate is respected).
- No nargo / bb / cargo run.
- No git fetch of ratified content (upstream origin/main UNMOVED at
    62cc527f; merge-base(i5, origin/main) == origin/main; i5 is 82 ahead
    / 0 behind; no rebase was required this round).
- No lease/cron/delivery actions (the round is in-band inside the
    regular 20-minute cadence lease; no monitor-event fire triggered).
- No owner poke / no escalation messages.

## Files this round (all under poc/)

- poc/r140_gate_source_check/README.md          (this file)
- poc/r140_gate_source_check/RAN.out             (verbatim probe output)
- poc/r140_gate_source_check/visits.py           (re-runnable probe)

Existing in-tree files touched this round: NONE.

## Caveats (honest scope limits)

- The fiber bound 2^474,881 is an ENTROPY/pigeonhole LOWER bound on a
  generic in-box witness: it counts in-box coordinate vectors per acc
  value, not proven colliding witness pairs. It shows the acc-pin +
  range box cannot be injective; it does not exhibit a concrete
  in-box collision (the r136 kernel vector is the natural candidate,
  and it is out-of-box by 197 bits).
- The acc-pin in the r137 consumer probe runs over the FLATTENED
  payload (N * BIT_MSG = 475,136 slots of ~58-bit limbs), not over
  raw 255-bit field coefficients. The entropy ceiling uses N * bits(Q)
  as the in-box secret size, matching that flattened representation.
- Whether "safe" is satisfied by CRYPTOGRAPHIC collision resistance of
  the producer commitments (rather than by kernel closure) is a
  different security-model question the r140 line does not state. If
  the producer's safe sponge is assumed collision-secure, the
  consumer re-binding question becomes "how much independent
  computation must a consumer do to confirm the producer claims,"
  and the 2,732-g acc-pin cell class is one (cheap) answer to that
  question; this round's kernel-closure analysis answers a DIFFERENT
  (constraint-satisfaction) formulation.
- This round does NOT change the r140 persistent line, does NOT touch
  r140's owner-gate state, and does NOT commit any circuit/crates
  source. Design-side verification only, recorded for the owner
  re-gate decision.
