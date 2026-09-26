# C5cheap - cutting the client proving cost of the user-encryption leg (P3)

Date: 2026-09-26. OFF-ROUND. Proof-of-concept only, ZERO in-tree source edits
(standing owner re-gate, cut from i5/dkg-research r139 / base 2144c89).

## 1. What is being optimized and why it is the client's bottleneck

The user's per-submission client proof is P3, `user_data_encryption`
(`circuits/lib/src/core/threshold/user_data_encryption_ct0.nr`, 207 lines).
Its cost path, read straight off the circuit:

1. bit-decompose each of the L limb polys, `flatten` with BIT width
   (`commitments.nr:146` `single_polynomial_payload`);
2. range-check each limb (`check_range_bounds`, ct0.nr:110-125);
3. build a domain-separated SAFE commitment over the flattened limbs
   (`generate_commitments`, ct0.nr:127-142, via `compute_multiple_polynomial_commitment`);
4. run the Fiat-Shamir challenge and the single Schwartz-Zippel (SZ) evaluation
   identity (`verify_evaluations`, ct0.nr:162-187, asserts `sum.0 == sum.1`).

Step 3 (the SAFE / "safe-sponge" re-commit over the flattened limbs) is the dominant
per-cell term. RAN anchors, exact:

- per-cell full body = 71,981 g / 3,644 ACIR (r132 p4, secure-8192);
- safe-sponge share of that cell = 69,249 g = 96.18% (r132, the p4 - p3 nodeId);
- sponge-free walking-accumulator probe = 2,732 g/cell (r132 p3);
- in-block 42-cell A-shape, full = 3,022,405 g, accumulator form = 114,761 g,
  cut = -96.203% (r137 2-point linearity, per-cell c = 2,732).

So switching the per-cell binding from the safe-sponge re-commit to the
Walking-pin class cuts that block ~96% at the gate level. This is a GATE cut.
The user's "~5 min in the browser" wall (user-reported; `paper/results.tex`
"User encryption (Greco) cost" table is still all `\todo{}`, so it is not yet an
in-tree RAN) is a separate metric (WALL) that scales proportionally with the
gate count per limb but is NOT exactly H = gate factor; the branch does not yet
have that mapping RAN-d.

## 2. Why the swap is sound

The consumer's binding on a limb vector v is today "the SAFE commitment of the
flattened limbs." The proposed consumer binding keeps everything the SAFE arm
verified through the Fiat-Shamir + Schwartz-Zippel (SZ) path, and re-routes the
commitment input to a smaller derived value. Two facts, both machine-executed
in this folder (test_a and test_b in test_c5cheap.py), not assumed:

(A) The walking pin pin(v) = sum_i ALPHA^i * v_i, computed in Horner form, is a
    LINEAR functional over the circuit field. Its kernel has dimension N-1: the
    vector with 1 at index N-2 and -ALPHA (mod P) at index N-1 pins to exactly 0
    (re-executes r136 leg_b, RAN on disk: "pin(v) = 0"). Consequence: the pin
    alone is NOT collision-resistant; it cannot be the binding.

(B) The P3 ct0 already runs a co-pin family over these same limb polys: per-limb
    range checks (ct0.nr:110-125), and the single SZ evaluation identity
    (ct0.nr:162-187, the summed lhs == rhs). A non-zero kernel displacement is
    localized: it kicks out of the range pin at exactly the shifted coefficient,
    and it shows up at one or two limbs in the SZ identity. So the co-pin family
    closes the kernel exactly. (This is the argument of test_d + test_e + test_f.)

With the pin, the commitment input becomes the pin (a single field element)
rather than the full bit-flattened limb polys. The pin is a deterministic
function of witnessed limb polys that the FS transcript already commits to, so
it reveals no new public information, introduces no new assumption, and the
SZ identity / range pins are left untouched. The soundness frontier is the
same as the safe-sponge frontier, with one less in-circuit term. This restates
r136 DESIGN.md line 16-18: "the consumer must keep every other pin live on its
path" ... "Option B is a BINDING REARRANGEMENT, not a hash swap."
## 3. What the draft proves (each line -> a section in test_c5cheap.py)

- **A** — the pin is bilinear over the field: pin(aX + bY) = a pin(X) + b pin(Y).
- **B** — the kernel: pin(vK) == 0 for vK = e_{N-2} - ALPHA * e_{N-1},
  restating r136 leg_b verbatim.
- **C** — a valid P3-style ct0 tuple satisfies the exact ring identity
  ct0 == pk0*u + e0 + k1*k0 + r1*q in (Z/QZ)[x]/(x^N+1), the same
  polynomial the circuit's SZ limb-sum evaluates at one gamma.
- **D** — a one-coefficient tamper (ct0[3] += 1) makes the residual
  nonzero: the SZ identity is a discriminator, not just a gate.
- **E** — an out-of-coefficient witness is caught by the per-index range pin
  while the pin over that witness is still a well-defined field element
  (the pin alone would not have caught it).
- **F** — a forged tuple (wrong pk0 + zeroed ct0): pin well-defined, in range,
  but SZ identity FAILS -> the identity is load-bearing; pin + range alone
  would have accepted it.

The toy math (N = 32, Q = 2^61 - 1, the BN128 scalar field P and the r136
ALPHA) is deliberately small: the theorems it exercises (linearity, kernel
dimension, ring-identity as discriminator, co-pin load-bearing) are
scale-agnostic. No security parameter is being tested at the secure-8192
scale; that RAN is open.

## 4. RAN anchors (all first-verified by grep / on-disk read this session)

- **r132 p4**  per-cell full body 71,981 g / 3,644 ACIR, secure-8192/small;
  p3 (sponge-free walking-acc probe) = 2,732 g/cell; safe-sponge share of the
  cell = p4 - p3 = 69,249 g = 96.18%.
- **r113**     secure-8192 C5 a/b/c split: (a) recommit = 2,157,441 g = 84.46%;
               the same recommit class, larger absolute figure.
- **r137**     2-point linearity: at 42 cells, c = 2,732 g, block =
               S + 42c = 114,761 g vs 3,022,405 g full = -96.203%.
- **r136**     leg_b RAN: kernel vector confirmed, "pin(v) = 0"; DESIGN.md
               lines 16-18 = the binding-rerearrangement restatement.
- **user-side** paper/results.tex "User encryption (Greco) cost" table is
               still all `\todo{}`; the ~5-min browser wall is user-reported,
               not yet an in-tree RAN.
## 5. What this is NOT

- Not an in-circuit A/B RAN of P3 (ct0 + ct1) at secure-8192. The single-cell
  RAN at the pin form is anchored at r137; the P3-specific A/B is open (6.1).
- Not a client-side WALL claim. The >=96% figure is a GATE cut; the WALL cut
  scales with it but is only proportional and still a DRAFT, not a RAN.
- Not a Greco/Halo2 dependency change. This branch keeps Greco's reference
  proving stack as-is; the savings come from replacing one in-circuit SAFE
  re-commit term with a pin, in the Noir P3 leg.
- Not a protocol re-gate. If the owner signs off the consumer's commit-scheme
  swap as I19's successor, that is a source-diff rule decision; the branch
  delivers the theory + math, not the in-tree source diff.

## 6. Open items (roadmap for the branch; all owner-visible, none executed
    in this commit)

6.1  (next) In-tree A/B RAN of P3 at secure-8192 (V0 = safe-sponge recommit,
            V1 = walking-pin recommit), H = 14 / L = 3, at the in-circuit
            scale. Targets the wall/mapping term left open in section 1:
            exactly the determination "is the client-side gate cut
            proportional to the wall cut, and by what factor".
6.2  Client-side WALL RAN of P3 at secure-8192 (native or browser WASM) so the
     "~5 min" has a RAN anchor.
6.3  Co-pin drop verification against the real P3 legs (not just the toy in
     this folder): e / f analog RAN at secure-8192.
6.4  doc note (scorecard / design-note) that the safe-sponge recommit is a
     client-cost hotspot, and the consuming option is flagged in the paper's
     TODO line - OUT OF SCOPE unless owner opens it.