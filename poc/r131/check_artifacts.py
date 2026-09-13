#!/usr/bin/env python3
import json, re, math, os

os.chdir('/home/dev/interfold-research/interfold/poc/r131')
for pro in ['c4_v0', 'c4_v1', 'c5_v0', 'c5_v1']:
    try:
        a = json.load(open(pro + '_artifact.json'))
        inA = a['intermediates']['recommit-4-2a-Common']
        vks = inA.get('verification_keys', [])
        sizes = [v.get('size') for v in vks]
        log = [round(math.log2(s), 2) if s else None for s in sizes]
        print(pro, 'K', len(vks), 'sizes', sizes, 'log2', log)
    except Exception as e:
        print(pro, 'ERR', repr(e))

for f in ['c4_v0', 'c4_v1', 'c5_v0', 'c5_v1', 'c5_v2']:
    t = open(f + '_run.out').read()
    rt = [l for l in t.splitlines() if 'Real' in l or 'Maximum resident' in l or 'Percentage of CPU' in l]
    print('==', f, rt)