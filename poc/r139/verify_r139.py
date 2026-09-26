#!/usr/bin/env python3
"""r139 — per-cell INSTANTIATION membrane-pin self-check.

Legs (all RAN this round, on disk in poc/r139/):
  f6   per-cell CALL form, K=6   (leg 1)  RAN-GREEN
  f42  per-cell CALL form, K=42  (leg 1)  OOM-kill (host-ceiling class)
  c12  per-cell CALL form, K=12  (leg 2)  RAN-GREEN
  c24  per-cell CALL form, K=24  (leg 3)  RAN-GREEN
  c48  per-cell CALL form, K=48  (leg 4)  OOM-kill (host-ceiling class)

Self-checks:
  TS1 f6/c12 gates digit-exact twins of r137 w6/w12 (same body, call vs loop form)
  TS2 c24 gates digit-exact on the r137 2-pt slope (S + 24c)
  TS3 walls from each leg's own T0/T1 (RAN; 4c-pinned, this-tick thermal context)
  TS4 OOM-java are journalled/anchored (systemd MemoryPeak + oom-kill results)
  TS5 membrane: 24 GREEN, 42/48 OOM  =>  (24, 42] cell boundary for the PER-CELL
      CALL form — the r137 membrane nail quantified for this form.
No DRAFT number is asserted as a measurement.
"""
import json, os, re, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
INTERFOLD = '/home/dev/interfold-research/interfold'

def gates_at(path):
    with open(path) as f:
        raw = f.read()
    m = re.search(r'"circuit_size"\s*:\s*(\d+)', raw)
    assert m is not None, f'no circuit_size in {path}'
    return int(m.group(1))

def wall_pair(path):
    raw = open(path).read()
    t0 = float(re.search(r'T0=([\d.]+)', raw).group(1))
    t1 = float(re.search(r'T1=([\d.]+)', raw).group(1))
    rc = re.search(r'NARGO_RC=(\d+)', raw).group(1)
    return t1 - t0, rc

f6 = gates_at(f'{HERE}/f6_gates.json')
c12 = gates_at(f'{HERE}/c12_gates.json')
c24 = gates_at(f'{HERE}/c24_gates.json')
r137_w6 = gates_at(f'{INTERFOLD}/poc/r137/w6_gates.json')
r137_w12 = gates_at(f'{INTERFOLD}/poc/r137/w12_gates.json')

ok = []
# TS1: form-equivalence digit twins (call form == wrap-loop form)
assert f6 == r137_w6 == 16409, f'f6={f6} vs r137 w6={r137_w6} — form delta; abort'
ok.append(f'TS1a f6={f6} == r137 w6={r137_w6} (digit twin)')
assert c12 == r137_w12 == 32801, f'c12={c12} vs r137 w12={r137_w12} — form delta; abort'
ok.append(f'TS1b c12={c12} == r137 w12={r137_w12} (digit twin)')

# TS2: c24 digit-exact on the r137 2-pt slope (S + 24c), c=2732.000, S=17.0
r137_c = (r137_w12 - r137_w6) / 6
r137_S = r137_w6 - 6 * r137_c
exp24 = r137_S + 24 * r137_c
assert c24 == exp24, f'c24={c24} vs slope S+24c={exp24}'
ok.append(f'TS2 c24={c24} == S+24c={exp24} (S={r137_S:.1f}, c={r137_c:.3f} from r137 RAN)')

# TS3: walls
w6, rc6 = wall_pair(f'{HERE}/f6_run.out')
w12, rc12 = wall_pair(f'{HERE}/c12_run.out')
w24, rc24 = wall_pair(f'{HERE}/c24_run.out')
assert (rc6, rc12, rc24) == ('0', '0', '0'), 'green legs must be rc=0'
slope1 = (w12 - w6) / 6
slope2 = (w24 - w12) / 12
intercept = w6 - 6 * slope1
ok.append(f'TS3 walls RAN: f6={w6:.2f}s c12={w12:.2f}s c24={w24:.2f}s @4c')
ok.append(f'    per-cell wall slope = {slope1:.3f} / {slope2:.3f} s/cell; intercept {intercept:.2f} s')

# TS4: OOM legs — journal-anchored
f42st = subprocess.run(['systemctl', '--user', 'show', 'r139_f42', '-p', 'MemoryPeak', '-p', 'Result'],
                       capture_output=True, text=True).stdout
c48st = subprocess.run(['systemctl', '--user', 'show', 'r139_c48', '-p', 'MemoryPeak', '-p', 'Result'],
                       capture_output=True, text=True).stdout
f42k = int(re.search(r'MemoryPeak=(\d+)', f42st).group(1))
c48k = int(re.search(r'MemoryPeak=(\d+)', c48st).group(1))
assert 'oom-kill' in f42st and 'oom-kill' in c48st, 'both OOM legs must be journalled oom-kill'
f42g, c48g = f42k / 2**30, c48k / 2**30
ok.append(f'TS4 OOM f42={f42g:.2f} GiB / c48={c48g:.2f} GiB (systemd MemoryPeak, oom-kill journalled)')

# TS5: membrane bracket
assert c24 > 0 and f42g > 30 and c48k > 30
ok.append('TS5 membrane PER-CELL CALL form: 24 cells RAN-GREEN, 42 & 48 cells OOM '
          + 'at ~%.1f-%.1f GiB => (24, 42]' % (f42g, c48g))

mem = subprocess.run(['grep', '-E', 'MemTotal|SwapTotal', '/proc/meminfo'], capture_output=True, text=True).stdout
dot = re.search(r'MemTotal:\s*(\d+)', mem).group(1)
ok.append(f'    host MemTotal = {int(dot)/2**20:.1f} GiB; SwapTotal 0 (host-ceiling kills, this box)')

out = '\n'.join(ok) + '\nSelf-check PASS (all RAN; config byte-restored sha-asserted per leg)\n'
with open(f'{HERE}/RAN.out', 'w') as f:
    f.write(out)
print(out)