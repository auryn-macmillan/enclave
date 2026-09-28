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
    (ct0.nr:162-187, the summed lhs == rhs). The intent is that this family is
    what licenses using the pin as a binding. Whether it actually CLOSES the
    (N-1)-dim pin kernel over the in-box, in-circuit-satisfying set is exactly
    the question the suite below does NOT settle - section 2a states it.
    (test_d + test_e + test_f show the family catches specific displacements;
    they do not show it catches every one.)

With the pin, the commitment input becomes the pin (a single field element)
rather than the full bit-flattened limb polys. The pin is a deterministic
function of witnessed limb polys that the FS transcript already commits to, so
it reveals no new public information, introduces no new assumption, and the
SZ identity / range pins are left untouched. The soundness frontier is the
same as the safe-sponge frontier, with one less in-circuit term. This restates
r136 DESIGN.md line 16-18: "the consumer must keep every other pin live on its
path" ... "Option B is a BINDING REARRANGEMENT, not a hash swap."

## 2a. OPEN SOUNDNESS STATEMENT (labeled; NOT established by this branch)

The gate-cut number (section 1, -96.203%) does not depend on this; the *binding*
claim does. Stated out, separate from the cost result, because the suite that
passes in this folder does not settle it.

**The circuit-actual assertion (one point, not the full ring identity).**
`verify_evaluations` (ct0.nr:162-187) asserts a SINGLE field equality at one
evaluation point gamma (= gammas[0]). For each of the L limbs it forms

    ct0_rhs_i = pk0is[i](gamma) * u(gamma) + e0is[i](gamma)
               + k1(gamma) * k0is[i]
               + r1is[i](gamma) * qis[i]
               + r2is[i](gamma) * (gamma^N + 1)

and asserts
    sum_i gamma_i * ct0is[i](gamma)  ==  sum_i gamma_i * ct0_rhs_i,
with gamma_0 = 1 and gamma_i = gammas[i] for i >= 1. That is ONE field
equation. The full polynomial identity `residual == 0` in
(Z/QZ)[x]/(x^N+1) instead requires the residual to be the zero polynomial = N
independent coefficient constraints. V(circuit) therefore strictly contains
V(ring-identity).

**The kernel statement (the only question that matters).**
Let V be the set of witness tensors
    W = (pk0is, ct0is, u, e0, e0is, k1, r1is, r2is)
passing every in-circuit check (per-limb range box, ct0.nr:110-125; e0 CRT
consistency, ct0.nr:98-108; the one-point SZ assertion above). Let pi(W) be the
proposed pin (walking pin over the committed limb polys). The binding question
is:

    Is pi injective on V?  i.e., is there W != W' in V with pi(W) = pi(W')?

If such a pair exists, one who commits to pi and learns the channel that
distinguishes the two preimages succeeds; the binding is broken, and the
question this reduces to is short-integer-solution / bounds-SIS-shaped (find a
nonzero d in the (N-1)-dim pin kernel with pi(d) = 0 and W, W' both in-box
and in V). This is the expression of a SIS-type hardness; whether it is
actually hard at the concrete (N, q, box, gamma-dist) at secure-8192 is NOT
shown here. It depends on parameters, and needs either a reduction or a lattice
cost estimate, not the six tests below.

**What the suite (section 3) does and does NOT establish.**
- (A),(B): pin linear, kernel dim N-1. Kernels are linear; V is a quadratic /
  affine slice. Neither says anything about V.
- (C),(D),(F): test `residual == 0` (the N-constraint ring identity), a STRICTLY
  stronger condition than the circuit's one-point SZ. If Vr = {in-box W :
  residual(W) = 0} subset V, then (C) exhibits one W in Vr, (D) shows a single-
  coefficient tamper leaves Vr, and (F) shows a forged tuple leaves Vr. None of
  these is a search over V for a pi-collision, and none rules one out on
  V \ Vr. That residual set V minus Vr is exactly the surface the one-point
  assertion opens, and exactly where a small in-box d with pi(d) = 0 could
  register undetected. The tests searched Vr (smaller); the claim needs V.
- (E): range box catches an OOB witness; independent of pi.

So the honest status: (A),(B) are true; (C)-(F) hold on the stronger set Vr;
injectivity of pi on V is OPEN. This branch should not be read as settling it.

**Decision pointer (owner/architecture; none run in this branch).**
1. If the SZ residual at the fixed gamma, linearized in small displacements
   d, is affine in d, then a pi-collision on V is L-inf-bounded-SIS (short
   integer solution with a linear kernel subject to a box). An eSIS-style
   reduction suffices and is short.
2. The one-point residual is degree-2 in the witness, but with a narrow
   non-linearity: the ONLY monomial multiplying two varied witnesses is
   pk0is_i(gamma) * u(gamma). The pieces k1(gamma)*k0i and r1i(gamma)*q_i are
   LINEAR, because k0i and q_i are public scheme params (`configs`), not
   witnesses; and the e0 / r2 / ct0 terms are plainly linear. Since all L
   limbs share the single u(gamma), that term is the bilinear form
   u(gamma) * [sum_i gamma_i pk0is_i(gamma)] - rank-1. Hold u fixed (or keep
   the pk0-u perturbation off the other displacements) and the residual is
   affine in every remaining direction, so option 1's affine linearization is
   exact on all but that one rank-1 direction. If the bilinear term cannot be
   excluded, run a seeded Babai / LLL / kernel-solve over the concrete
   (N, q, box) at secure-8192 with the in-tree gamma distribution, and report
   the lower bound in bits; 128-or-better is the honest floor.
3. Cheapest closure: keep the safe-sponge / collision-resistant binding as the
   EXTERNAL commit (H(ct)) and demote the pin to an internal compression of the
   proof's own FS machinery. Then the two-witness pi-collision question only
   has to be answered for whatever the proof is internally bound to, and the
   app-side trust model is the hash, collision-resistant by construction.

(2a) is the open item that extends 6.3.

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