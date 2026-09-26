// SPDX-License-Identifier: LGPL-3.0-only
//
// r133 A1 — BINDING-SHAPE A/B arm 1: the ISOLATED per-cell MERKLE-NODE shape at the
// production commit point (CG-0: secure-8192/small, N=8192, BIT_MSG=58).
// Wire shape of the replacement scheme's producer-side cell:
//   the producer commits each share cell to a commitment leaf with the REAL leaf
//   commitment function (same class as C2's party-share and C3's message commits),
//   then dilutes the two commitment leaves into ONE SAFE node; the node OUT is
//   pinned to a second pub input (the grid commitment binding). The two commitment
//   leaves are unconstrained public intermediates -> the snapshot stay LIVE
//   (no optimiser camping, the pin-protocol of r131/np2) while the binding level
//   costs exactly ONE sponge per cell (the np2 unit, r131 RAN 40,618 g).
use lib::configs::default::dkg::{N, SHARE_ENCRYPTION_BIT_MSG};
use lib::math::commitments::{
    compute_commitment, compute_share_encryption_commitment_from_message,
};
use lib::math::polynomial::Polynomial;

fn main(
    sk_share: Polynomial<N>,
    esm_share: Polynomial<N>,
    ds: pub [u8; 64],
    expected: pub Field,
) {
    let skc = compute_share_encryption_commitment_from_message::<N, SHARE_ENCRYPTION_BIT_MSG>(
        sk_share,
    );
    let esc = compute_share_encryption_commitment_from_message::<N, SHARE_ENCRYPTION_BIT_MSG>(
        esm_share,
    );
    let node = compute_commitment([skc, esc], ds);
    assert(node == expected, "pin");
}