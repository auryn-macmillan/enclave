# C5cheap - Cheap Binding for the Client-Side Lattice Commitment

Status: Draft reference implementation. This version of the README tracks the work done
in this round; the full theory text (with all RAN citations) ships as THEORY.md in a
later commit of this branch.

## Scope
- Off-round, pocs only. No circuit/crate source edits (owner re-gate per 2026-09-12 rule).
- Stands behind i5/dkg-research r139 (base commit 2144c89).
- Wall claim: the in-circuit safe-sponge recommit term drops from ~71,981 g/cell (r132,
  secure-8192) to ~2,732 g/cell (r137 per-linear accumulator form), a **-96.203 % gate
  reduction** at the in-block A-shape. Client-side WALL impact is PROPORTIONAL but the
  exact wall factor is DRAFT (no client-side RAN at P3 in the tree yet - paper/results.tex
  table is \todo{}).

## What this folder contains
- c5cheap.py       - reference model of the binding (walking pin + range + SZ)
- test_c5cheap.py  - 6-check test suite (linearity, kernel, ring identity, tamper, range, load-bearing SZ)
- RAN.out          - captured PASS output
- THEORY.md        - (to be authored; this README summarizes the in-flight state)

## How to run
python3 test_c5cheap.py

Expected: 6/6 PASS, exit 0.