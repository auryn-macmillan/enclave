#!/usr/bin/env python3
# r131 verbatim-copy audit (v2, self-checked): re-derives the probe bodies from the CURRENT
# production sources (@ HEAD) and diffs the CODE (comments stripped, indentation-normalized)
# against the arm copies in poc/r131. The only admissible deviations: (1) the `_v0copy` suffix
# on fn names, (2) `self.`-inlining in the copies (self.decrypted_shares->decrypted_shares,
# self.configs.qis->qis, self.pk0->pk0, self.pk0_agg->pk0_agg, pk->pk0, pk_agg->pk0_agg in the
# C5 inline). Anything else is a FAIL.
import difflib, re, sys

ROOT = '/home/dev/interfold-research/interfold'

def extract_fn(text, sig_start):
    i = text.find(sig_start)
    assert i >= 0, 'signature not found: ' + sig_start
    i = text.rfind('\n', 0, i) + 1
    depth = 0
    started = False
    j = i
    while j < len(text):
        c = text[j]
        if c == '{':
            depth += 1
            started = True
        elif c == '}':
            depth -= 1
            if started and depth == 0:
                j += 1
                break
        j += 1
    return text[i:j]

def no_comments(s):
    out = []
    for line in s.splitlines():
        t = line.strip()
        if t.startswith('//'):
            continue
        out.append(t)
    return '\n'.join(out)

def norm_code(s):
    # strip comments, de-indent every line, drop blank lines, collapse whitespace
    lines = [re.sub(r'\s+', ' ', l).strip() for l in no_comments(s).splitlines()]
    return [l for l in lines if l]

def code_equal_with_fitness(src, copy_map, label):
    src_lines = norm_code(src)
    for key, val in copy_map.items():
        src_lines = [l.replace(key, val) for l in src_lines]
    copy_lines = norm_code(copy_map._copy if hasattr(copy_map, '_copy') else '')
    return src_lines, copy_lines

checks = []
def check(name, a, b, a_label, b_label):
    dd = [d for d in difflib.unified_diff(a, b, a_label, b_label, lineterm='')]
    passed = not dd
    checks.append(passed)
    print(('PASS ' if passed else 'FAIL ') + name)
    for d in dd[:40]:
        print(d)
    return passed

re_dkg = open(ROOT + '/circuits/lib/src/core/dkg/share_decryption.nr').read()
re_c5 = open(ROOT + '/circuits/lib/src/core/threshold/pk_aggregation.nr').read()
v1 = no_comments(open(ROOT + '/poc/r131/v1/src/main.nr').read())
v2 = no_comments(open(ROOT + '/poc/r131/v2/src/main.nr').read())
c5v1 = no_comments(open(ROOT + '/poc/r131/c5_v1/src/main.nr').read())

src_agg = extract_fn(re_dkg, 'fn compute_aggregated_shares(')
src_norm = extract_fn(re_dkg, 'fn normalize_aggregated<let N: u32, let L: u32>')
src_verb = extract_fn(re_c5, 'fn verify_pk_for_basis(')

# C4 v1 copy of compute_aggregated_shares: same body, renamed fn + de-self-ified param
v1_agg = extract_fn(v1, 'fn compute_aggregated_shares_v0copy<')
apply = lambda src, pairs: '\n'.join('\n'.join(src.splitlines()) and [re.sub(r'\s+', ' ', l).strip() for l in src.splitlines()])
def maplines(lines, pairs):
    out = []
    for l in lines:
        for k, v in pairs:
            l = l.replace(k, v)
        out.append(l)
    return out

c4_pairs = [
    ('fn compute_aggregated_shares(self) ->', 'fn compute_aggregated_shares_v0copy<placeholder>'),
    ('self.decrypted_shares', 'decrypted_shares'),
    ('-> [Polynomial<N>; L] {', '-> [Polynomial<N>; L] {'),
]
# Simpler: compare BODIES (drop the signature line, which is legally different).
def body_lines(fn_text, drop_first_n_sig=2, body_anchor=None):
    ls = norm_code(fn_text)
    if body_anchor:
        # compare from the first body line after the signature brace (robust to multi-line sigs)
        i = next(i for i, l in enumerate(ls) if body_anchor in l)
        return ls[i:]
    idx = next(i for i, l in enumerate(ls) if l.endswith('{'))
    return ls[idx:]  # includes the '{' line

srcagg_b = body_lines(src_agg, body_anchor='let mut sum:')
v1agg_b = body_lines(v1_agg, body_anchor='let mut sum:')
srcagg_mon = maplines(srcagg_b, [('self.decrypted_shares', 'decrypted_shares')])
check('C4 v1: compute_aggregated_shares body verbatim (self-de-referenced)', srcagg_mon, v1agg_b, 'src', 'v1copy')

srcnorm_b = body_lines(src_norm)
v1norm_b = body_lines(extract_fn(v1, 'fn normalize_aggregated_v0copy<'))
v2norm_b = body_lines(extract_fn(v2, 'fn normalize_aggregated_v0copy<'))
check('C4 v1: normalize_aggregated body verbatim', srcnorm_b, v1norm_b, 'src', 'v1copy')
check('C4 v2: normalize_aggregated body verbatim', srcnorm_b, v2norm_b, 'src', 'v2copy')

# C5 v1 inline: the loop body starts at `let q_l = qis[basis_idx];` (src: `self.configs.qis`)
srcverb_b = norm_code(src_verb)
i = next(i for i, l in enumerate(srcverb_b) if l.startswith('let q_l ='))
src_body = srcverb_b[i:]
m = c5v1.find('let q_l = qis[basis_idx];')
m2 = c5v1.find('compute_pk_aggregation_commitment::<N, L', m)
mine = [re.sub(r'\s+', ' ', l).strip() for l in c5v1[m:m2].splitlines()]
mine = [l for l in mine if l]
# de-self-ify + rename the loop vars used in the source signature (pk, pk_agg)
srcmap = maplines(src_body, [
    ('self.configs.qis', 'qis'),
    ('self.pk0_agg', 'pk0_agg'),
    ('self.pk0', 'pk0'),
    ('pk_agg[basis_idx]', 'pk0_agg[basis_idx]'),
    ('pk[party_idx]', 'pk0[party_idx]'),
])
check('C5 v1: verify_pk_for_basis loop body verbatim (self-inlined)', srcmap, mine, 'src-inlined', 'c5_v1')

# C4 v2 fixed-point check: normalize called on `decrypted_shares` (not an aggregated variable)
i = v2.find('normalize_aggregated_v0copy::<N, L_THRESHOLD>(')
call = v2[i:i + 120]
ok_fp = 'decrypted_shares' in call
print(('PASS ' if ok_fp else 'FAIL ') + 'C4 v2: normalize fixed-pointed on decrypted_shares (no H-fold)')
checks.append(ok_fp)

print('AUDIT', 'OK (all bodies verbatim vs production @ HEAD)' if all(checks) else 'MISMATCH')
sys.exit(0 if all(checks) else 1)