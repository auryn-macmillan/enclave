#!/usr/bin/env python3
import json, re, os, math

os.chdir('/home/dev/interfold-research/interfold/poc/r131')

def gates(pro):
    t = open(pro + '_gates.json').read()
    # strip leading non-JSON noise (epilogue/spew lines)
    i = t.find('{')
    d = json.loads(t[i:])
    fns = d.get('functions', [])
    # circuit_size per function
    sizes = [(f.get('circuit_size'), f.get('acir_opcodes')) for f in fns]
    line1 = t.splitlines()[0]
    return sizes, line1

def wall(pro):
    t = open(pro + '_run.out').read()
    m = re.search(r'Elapsed \(wall clock\) time \(h:mm:ss or m:ss\): (.+)', t)
    mm = re.search(r'Maximum resident set size \(kbytes\): (\d+)', t)
    cpu = re.search(r'Percent of CPU this job got: (\d+)', t)
    us = re.search(r'User time \(seconds\): ([\d.]+)', t)
    def wage(s):
        if ':' in s:
            p = s.split(':')
            h = int(p[0])
            mmin = int(p[1])
            sec = float(p[2])
            return h * 3600 + mmin * 60 + sec
        return float(s)
    return (wage(m.group(1)) if m else None,
            int(mm.group(1)) / (1024 * 1024) if mm else None,
            cpu.group(1) if cpu else None,
            us.group(1) if us else None)

for pro in ['c4_v0', 'c4_v1', 'c5_v0', 'c5_v1', 'c5_v2']:
    g = None
    try:
        sizes, line1 = gates(pro)
        tot = sum(s[0] for s in sizes)
        g = 'circuit_sizes=%s acir=%s TOTAL=%d | %s' % (
            [s[0] for s in sizes], [s[1] for s in sizes], tot, line1)
    except Exception as e:
        g = 'GATE-PARSE-ERR ' + repr(e)
    w = wall(pro)
    print('%-7s wall=%5.1fs rss=%6.2fGiB cpu=%s%% user=%ss' % (pro, w[0] or -1, w[1] or -1, w[2], w[3]))
    print('        ', g)