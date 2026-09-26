// SPDX-License-Identifier: LGPL-3.0-only
//
// r135 V2 — the 42-cell (H=14 x L=3) DIRECT-SHA producer-attest BLOCK at the
// production commit point. r135 leg-1 (bpa) was DEFECTIVE: `use lib::configs::
// default::dkg::{L as L_THRESHOLD}` resolved L from dkg.nr (L=2, the secure
// QIS count) -- the flat fluent re-export in default/mod.nr -- so the block
// compiled at 28 cells and 71,981 g/cell (2,014,982 g). The production C4
// re-commit block uses the THRESHOLD config's L=3 (L_THRESHOLD), so the
// 42-cell shape (r134 anchor: 42 x 71,981 = 3,023,202 ~= 3,022,405 RAN h14_v0-v1)
// is the like-for-like cell count. This arm fixes the import to
// `configs::secure::threshold::L`. r133 b1 shape restated at H=14: per
// (honest, modulus) slot the producer re-hashes the share through the REAL
// C4 verify sponge (compute_share_encryption_commitment_from_message) and
// pins each commitment to a pub cell (r131/np2 pin-protocol). Liveness: all
// 42 outputs asserted against pub pins -> all sponges live.
use lib::configs::committee::active::H;
use lib::configs::default::dkg::{N, SHARE_ENCRYPTION_BIT_MSG};
use lib::configs::secure::threshold::L;
use lib::math::commitments::compute_share_encryption_commitment_from_message;
use lib::math::polynomial::Polynomial;

fn main(
    shares: [[Polynomial<N>; L]; H],
    expected: pub [[Field; L]; H],
) {
    for h in 0..H {
        for l in 0..L {
            let out = compute_share_encryption_commitment_from_message::<N, SHARE_ENCRYPTION_BIT_MSG>(
                shares[h][l],
            );
            assert(out == expected[h][l], "pin");
        }
    }
}