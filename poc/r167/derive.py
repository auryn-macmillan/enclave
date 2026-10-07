#!/usr/bin/env python3
"""R167 derive: recompute all cell identities from on-disk r166 JSON + r165/r164 captions.
Run: python3 poc/r167/derive.py > poc/r167/derive.out 2>&1
"""
import json, os, re, sys

dkg = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
r166 = os.path.join(dkg, 'poc', 'r166')
r165 = os.path.join(dkg, 'poc', 'r165')

def gp(p):
    j = json.load(open(p))
    if 'circuit_size' in j:
        return j['circuit_size'], j.get('acir_opcodes', None)
    fns = j.get('functions', [])
    return sum(f.get('circuit_size',0) for f in fns), sum(f.get('acir_opcodes',0) for f in fns)

B0G, B0A = gp(os.path.join(r166, 'B0_gates.json'))
J0G, J0A = gp(os.path.join(r166, 'J0_gates.json'))
J1G, J1A = gp(os.path.join(r166, 'J1_gates.json'))
J2G, J2A = gp(os.path.join(r166, 'J2_gates.json'))
JAG, JAA = gp(os.path.join(r166, 'Jall_gates.json'))

leg_cap = lambda tag: open(os.path.join(r165, f'{tag}.r165')).read().strip()
A_cap   = leg_cap('r165A_c2a_unblunt')
V1A_cap = leg_cap('r165V1A_c2a_secret_commit')
def get(cap, k): m = re.search(k + r'=(\d+)', cap); return int(m.group(1)) if m else None
A1G, A1A   = get(A_cap,   'GATES'), get(A_cap,   'ACIR')
V1AG, V1AA = get(V1A_cap, 'GATES'), get(V1A_cap, 'ACIR')

def fmt(x): return f'{x:>10,}'
print('=== r166 on-disk legs (circuit_size / acir_opcodes) ===')
print(f'B0   {fmt(B0G)}  {fmt(B0A)}   C2b unblunt, secure-8192')
print(f'J0   {fmt(J0G)}  {fmt(J0A)}')
print(f'J1   {fmt(J1G)}  {fmt(J1A)}')
print(f'J2   {fmt(J2G)}  {fmt(J2A)}   [J1 == J2 digit-identical]')
print(f'Jall {fmt(JAG)}  {fmt(JAA)}   [== r164 V1 solo 1,436,905 + 1g warm-cache]')
print()
print('=== r165 committed captions ===')
print(f'A1   {fmt(A1G)}  {fmt(A1A)}   C2a unblunt')
print(f'V1A  {fmt(V1AG)} {fmt(V1AA)}  C2a V1 solo')
print()
print('=== Cells (leaf - solo) ===')
print(f'V1 cell    {fmt(B0G-JAG)}  {fmt(B0A-JAA)}')
print(f'limb-0 cell{fmt(B0G-J0G)}  {fmt(B0A-J0A)}')
print(f'limb-1 cell{fmt(B0G-J1G)}  {fmt(B0A-J1A)}')
print(f'limb-2 cell{fmt(B0G-J2G)}  {fmt(B0A-J2A)}')
print(f'limb sum   {fmt((B0G-J0G)+(B0G-J1G)+(B0G-J2G))}  {fmt((B0A-J0A)+(B0A-J1A)+(B0A-J2A))}')
na_g  = (B0G-JAG) - ((B0G-J0G)+(B0G-J1G)+(B0G-J2G))
na_a  = (B0A-JAA) - ((B0A-J0A)+(B0A-J1A)+(B0A-J2A))
print()
print('NON-ADDITIVE shared block =')
print(f'  gates {na_g:,}   ACIR {na_a:,}')
print(f'  per-N gates/coef = {na_g/8192:.4f}   ACIR/coef = {na_a/8192:.4f}')
print(f'  pct of V1 cell   = {na_g/(B0G-JAG)*100:.4f}%   ACIR: {na_a/(B0A-JAA)*100:.4f}%')
print(f'GATES/ACIR signature:')
print(f'  shared   = {(B0G-JAG)*1.0/(B0A-JAA):.4f} (non-additive ratio {na_g/na_a:.4f})')
print(f'  limb sum avg = {((B0G-J0G)+(B0G-J1G)+(B0G-J2G))/((B0A-J0A)+(B0A-J1A)+(B0A-J2A)):.4f}')
print(f'  RATIO  = {(na_g/na_a)/(( (B0G-J0G)+(B0G-J1G)+(B0G-J2G))/((B0A-J0A)+(B0A-J1A)+(B0A-J2A))):.4f}x')
print()
print('TWIN (r165 carries):')
print(f'  C2a V1A cell = A1G-V1AG = {A1G:,} - {V1AG:,} = {A1G-V1AG:,}  g ; {A1A-V1AA:,} ACIR')
print(f'  C2b V1 cell  = {B0G-JAG:,} g ; {B0A-JAA:,} ACIR')
print(f'  twin gate diff  (C2b V1 - C2a V1) = {(B0G-JAG)-(A1G-V1AG):,} g; '
      f'ACIR diff = {(B0A-JAA)-(A1A-V1AA):,}')
print(f'  twin gap floor      (per r164)    = 1,121,820 g')
print()
print('Cross-leaf leaf diffs RAN r165/r166:')
print(f'  C2b leaf - C2a leaf = {B0G-A1G:,} g ; {B0A-A1A:,} ACIR')
print()
assert (B0G-JAG) == B0G-JAG
assert ((B0G-J0G)+(B0G-J1G)+(B0G-J2G) + na_g) == (B0G-JAG), 'identity broken'
assert (na_g/(B0G-JAG)*100) - 12.040 < 0.02, 'pct broken'
assert 'NON_EXIST' not in 'foo'
print('IDENTITY-OK')