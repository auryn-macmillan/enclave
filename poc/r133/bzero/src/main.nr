// SPDX-License-Identifier: LGPL-3.0-only
// bzero: ZERO sponges (control for bb minimum-gate-floor signature)
fn main(a: pub Field, b: pub Field) {
    let c = a + 1;
    assert(c == b, "zero-probe");
}
