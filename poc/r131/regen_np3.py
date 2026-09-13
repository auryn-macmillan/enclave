#!/usr/bin/env python3
# Regenerate np3/src/main.nr programmatically (no transport-literal hex). ASCII-safe.
p = '/home/dev/interfold-research/interfold/poc/r131/np3/src/main.nr'

tag = b'R131_NO' + b'D3_00' + b'\x00\x00\x00\x00'
assert len(tag) == 16, len(tag)

def row(b):
    return '    ' + ', '.join('0x%02x' % x for x in b) + ','

assert len(b'\x00' * 16) == 16
hdr = """// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
//
// r131 node-cost probe B: ONE three-element SAFE commitment (commit([left, right,
// depth_salt]): the Merkle node shape WITH the depth position included, the
// conservative node model). Sister of np2 (2-element).
use lib::math::commitments::compute_commitment;

pub global DS_PROBE3: [u8; 64] = [
"""
body = '\n'.join([row(tag)] + [row(b'\x00' * 16) for _ in range(3)])
tail = """
    ];

fn main(left: pub Field, right: pub Field, salt: pub Field) -> pub Field {
    compute_commitment([left, right, salt], DS_PROBE3)
}
"""
txt = hdr + body + '\n' + tail
open(p, 'w').write(txt)
print('WROTE', p)

# verify on disk
import re
s = open(p).read()
allrows = re.findall(r'^(?:\s*0x[0-9a-f]{2}(?:, 0x[0-9a-f]{2})*)\s*$', s, re.M)
toks = []
for r in allrows:
    toks += re.findall(r'0x[0-9a-f]{2}', r)
print('BYTES', len(toks))
assert len(toks) == 64, 'byte count wrong: %d' % len(toks)
assert all(ord(c) < 128 for c in s), 'non-ascii present'
assert toks[13] == '0x30' and toks[14] == '0x30'
print('REGEN-OK')