#!/usr/bin/env python3
# Repair the np3 DS_PROBE3 array (transport garbled one byte). Rebuild all 4 lines exactly.
import re, sys

p = '/home/dev/interfold-research/interfold/poc/r131/np3/src/main.nr'
s = open(p).read()

tag = b'R131_NO' + b'D3_00' + b'\x00\x00'
assert len(tag) == 16, len(tag)
first_line_bytes = '0x' + ', 0x'.join(f'{b:02x}' for b in tag)
z = ', '.join('0x00' for _ in range(16))
new_arr = '[' + first_line_bytes + ',\n    ' + z + ',\n    ' + z + ',\n    ' + z + '\n];'

start = s.index('] -1', s...[truncated]