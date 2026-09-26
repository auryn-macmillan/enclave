// SPDX-License-Identifier: LGPL-3.0-only
//
// r133 A0 — BINDING-SHAPE A/B arm 0: the ISOLATED per-cell DIRECT-SHA reference at the
// production commit point (CG-0: secure-8192/small N=19/T=9/H=10, L=3, N=8192, BIT_MSG=58).
// This is the forward (non-reversed) twin of the r132 p4 body: C2's party-share commit
// orientation. Same public-shape semantics: one Field output pinned to a second pub input
// (r131/np2 pin-protocol: an unasserted pub output gets its sponge elided).
use lib::configs::default::dkg::{N, SHARE_ENCRYPTION_BIT_MSG};
use lib::math::commitments::compute_share_encryption_commitment_from_message;
use lib::math::polynomial::Polynomial;

fn main(
    share: Polynomial<N>,
    expected: pub Field,
) {
    let out = compute_share_encryption_commitment_from_message::<N, SHARE_ENCRYPTION_BIT_MSG>(
        share,
    );
    assert(out == expected, "pin");
}