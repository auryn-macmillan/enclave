# SPDX-License-Identifier: LGPL-3.0-only
"""
C5cheap - reference implementation of the binding-rearrangement theory.

This is a *reference* model of the client-proof binding, not a full FHE stack.
It isolates the two structures the theory turns on and proves, with real
polynomial arithmetic over a cyclotomic ring, that:

  (1) the linear "walking pin" pin(v) = sum alpha^i * v[i]  is a LINEAR
      functional with a one-dimensional-per-step kernel, so it ALONE is not
      collision resistant (r136 leg_b kernel check, restated in code);

  (2) the co-pin FAMILY (range + a linear parity pin + the Schwartz-Zippel
      evaluation identity used by P3 ct0 / user_data_encryption_ct0.nr)
      DOES bind the witness: two witnesses are distinguished by the family
      even when the walking pin collides;

  (3) dropping any single co-member of the family reopens the kernel attack.

All math is over R = (Z/qZ)[x]/(x^N + 1) with small N and q, so every
identity in the test suite is checked exactly (integer mod q), never rounded.
"""

# ---- field parameters -------------------------------------------------------
# r136 leg_b used the BN-style field below; the toy math only needs a prime.
P = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
ALPHA = 3641542188856621199          # r136 "A"

# Toy cyclotomic ring parameters (small, so poly even Newton eval is cheap).
N = 32                                # ring degree
Q = 2 ** 61 - 1                       # Mersenne coeff modulus (fast mod)


def walking_pin(v, alpha=ALPHA, p=P):
    """pin(v) = v0 + alpha*v1 + alpha^2*v2 + ...  (Horner form)."""
    acc = 0
    for x in v:
        acc = (acc * alpha + x) % p
    return acc


def kernel_vector(n, alpha=ALPHA, p=P):
    """A nonzero vector v with walking_pin(v) == 0.

    pin is Horner, so pin(v) = (...((v0)a + v1)...) with the LAST two
    coefficients free: choose v[n-2] = 1, v[n-1] = -alpha mod p. Every other
    coefficient is 0, so the running value reaches alpha * 1 + (-alpha) = 0.
    This is exactly r136's OID-1 kernel vector.
    """
    v = [0] * n
    v[n - 2] = 1
    v[n - 1] = (p - alpha) % p
    return v


# ---- toy cyclotomic ring R = (Z/qZ)[x]/(x^N + 1) ---------------------------

def poly_mul(a, b):
    """Multiply two R elements (len-N lists) mod x^N + 1."""
    out = [0] * N
    for i, ai in enumerate(a):
        if ai == 0:
            continue
        for j, bj in enumerate(b):
            if bj == 0:
                continue
            k = i + j
            if k < N:
                out[k] = (out[k] + ai * bj) % Q
            else:
                # x^(i+j) = x^(i+j-N) * x^N = -x^(i+j-N)
                out[k - N] = (out[k - N] - ai * bj) % Q
    return out


def poly_eval(p, gamma):
    """Evaluate R element at gamma, with the relation gamma^N = -1."""
    # Direct: sum p[i] gamma^i, reducing gamma^N = -1 by folding supers.
    out = 0
    for i in range(N):
        if p[i] == 0:
            continue
        out += p[i] * pow(gamma, i, Q)
    return out % Q


def poly_from_int(c):
    """Constant polynomial."""
    v = [0] * N
    v[0] = c % Q
    return v


# ---- a valid P3-ct0-style tuple, and the SZ evaluation identity -----------

def build_valid_tuple(rand_gamma, k0_list, q_list):
    """Construct witness polys that SATISFY the P3 ct0 identity exactly.

    Per limb i the ct0 recursion from user_data_encryption_ct0.nr is:
        ct0_i = pk0_i * u + e0_i + k1 * k0_i + r1_i * q_i + r2_i * (x^N + 1)
    Note (x^N + 1) = 0 in R, so the r2_i term vanishes by the ring relation;
    we keep r2_i in the identity as evaluated-1-check (matching the circuit,
    which multiplies by (gamma^N + 1) = 0 at a proper gamma only when gamma^N
    == -1, i.e. gamma is a 2N-th root of unity of odd index). For the REFERENCE
    we use the ring relation (ct0 = pk0*u + e0 + k1*k0 + r1*q) and note the
    circuit's SZ limb-sum is linear in ct0.

    We build forward so the identity holds by construction, then the test
    independently verifies it using a DIFFERENT evaluation point.
    """
    import random
    rng = random.Random(0xC5C)

    pk0  = [rng.randint(0, 10) for _ in range(N)]
    u    = [rng.randint(0, 10) for _ in range(N)]
    e0   = [rng.randint(0, 10) for _ in range(N)]
    k1   = [rng.randint(0, 10) for _ in range(N)]
    r1   = [rng.randint(0, 10) for _ in range(N)]
    r2   = [rng.randint(0, 10) for _ in range(N)]

    # ct0_i = pk0 * u + e0 + k1 * k0_i + r1 * q_i   (r2 term vanishes in R)
    pk0_u = poly_mul(pk0, u)
    k1_k0 = poly_mul(k1, k0_list)
    r1_q  = poly_mul(r1, q_list)
    acc = [0] * N
    for i in range(N):
        acc[i] = (pk0_u[i] + e0[i] + k1_k0[i] + r1_q[i]) % Q
    ct0 = acc
    # r2 term: + r2 * (x^N+1) == 0 in R, so ct0 unchanged. (kept for parity)

    return {
        "pk0": pk0, "u": u, "e0": e0, "k1": k1,
        "r1": r1, "r2": r2,
        "k0": k0_list, "q": q_list, "ct0": ct0,
    }


def ring_identity_residual(t):
    """Return ct0 - (pk0*u + e0 + k1*k0 + r1*q) in the ring R.

    This is the exact polynomial identity the P3-ct0 execution asserts
    (user_data_encryption_ct0.nr verify_evaluations: ct0_lhs == ct0_rhs, with
    the r2_i * (x^N + 1) term zero because (x^N + 1) == 0 in R). It equals the
    zero polynomial IFF the witness-derived factors actually produced ct0.
    The ZK circuit checks the preimage of this identity at one random gamma via
    Schwartz-Zippel; here we check the ring identity exactly (stronger: a
    nonzero residual is not merely unlikely, it is guaranteed to be nonzero).
    """
    terms = [poly_mul(t["pk0"], t["u"]), t["e0"],
             poly_mul(t["k1"], t["k0"]), poly_mul(t["r1"], t["q"])]
    acc = [0] * N
    for term in terms:
        acc = [(acc[i] + term[i]) % Q for i in range(N)]
    return [(t["ct0"][i] - acc[i]) % Q for i in range(N)]


def ring_identity_holds(t):
    return ring_identity_residual(t) == [0] * N


def parity_pin(v, alpha=ALPHA, p=P):
    """Second independent linear pin (different stride) over the same field."""
    acc = 0
    for i, x in enumerate(v):
        acc = (acc * (alpha + 2 + i) + x) % p
    return acc


def range_ok(v, bound):
    """Per-coefficient bound check (toy model of RANGE class)."""
    return all(0 <= x <= bound for x in v)
