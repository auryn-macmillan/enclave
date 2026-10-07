# r171 - DKG family-table aggregate receipt (0-compile)

The single-source, zero-compile Python re-derivation of the 6-row fold-base
DKG family table that r156 through r170 have built up one cell at a time.
Instead of re-running nargo/bb this round, we parse the **40 committed
`*_gates.json`** receipts already on disk (r156 C3 A/B/C + r157 C1 A1/B/C +
r158 C2a A/B/C + r159 C1 B + r160 C3 M + r161 C3 A1/U/E0/E1/X + r163 C2b
E1/B/C + r164 C2b V1/V2/V4/V5 + r165 C2a V1A/V2A + r166 B0/J0/J1/J2/Jall +
r169 no-sponge S + r170 C1 eek/sk) and re-assemble every per-leaf family
split, non-family block split, and cross-round identity check from those
digits.

Every number in this receipt file is either (a) a direct read of an on-disk
`*_gates.json` JSON, or (b) a python subtraction/Addition of (a) values with
the round's established identity (family = live - fullfn_NOP; per-limb =
live - limb_scaffold_NOP; flat = limbs - full; block_i = live - solo_i).
No nargo, no bb, no cargo, no Rust, no .nr touched. 0-compile round.

## Findings (RAN re-derivation, digit-exact vs the goldens cited in r156-r170)

| row | live     | family    | per-limb  | flat     | cells known from prior rounds |
|-----|----------|-----------|-----------|----------|-------------------------------|
| C0  |  -       |     0     |    n/a    |    0     |  -                            |
| C1  | 1,634,722| 1,014,519 |   811,013 |  203,506 | e_sm_lifted(127,023 r159) / eek(36,864 r170) / sk(36,869 r170) |
| C2a | 1,464,743|   552,965 |   552,965 | 0        |  flat 0 (r158)                 |
| C2b | 2,586,563|   552,965 |   552,965 | 0        |  flat 0 (r163)                 |
| C3  | 2,124,549|   729,117 |   557,065 |  172,052 | message(61,440 r160) + u/e0/e1(110,612 r161, 3-solo sum 184,340, excess 73,728) |
| C4  |  -       |     0     |    n/a    |    0     |  -                            |
| POOL|           | 2,849,566 |           |          |  r160 golden digit-exact       |

Family pool re-derives to **2,849,566 g = 30.983%** of the 9,197,169 g
r160-cited DKG total. Residual C0+C4 = 1,386,592 g (cited from r160, NOT
reburned this round - the live/gates for C0 and C4 receipts are not on disk
for this tree; they are summarized in r160's plan but the JSONs were not
kept).

## Cross-leaf byte-identity

Across the twins: **C2a V1A solo (1,436,905 g) == C2b V1 solo** (1,436,905 g,
RAN digit-exact via r165 + r164 on-disk JSONs). Verified in this round.

## Non-additive solver-CSE flavours re-confirmed from digits

- C3 narrow-flat (r161): 3-solo sum 184,340 g vs combined X 110,612 g.
  Excess **73,728 g** (one e0-sized cell over-counted when summed cell-by-cell
  instead of cut together). RAN digit-exact.
- C2b per-limb (r166): J1 == J2 byte-identical (314,026 g each); 3-limb sum
  1,011,237 g vs V1 cell 1,149,657 g; non-additive shared block **138,420 g**.
- C2b V1 block (r169): X (207,553 g) exceeds the block by 69,133 g. Density
  ratio X/block = 1.4994 (close to 1.5x).
- C1 (r170): 3-solo sum 200,756 g vs C1 flat 203,506 g. Residual **2,750 g**
  = 1.35% of the flat (r161-class small non-additivity).

## What this round adds on top of r156-r170

1. A single-execution re-derivation that the *cut-level identity per-leaf*
   holds digit-exact from the tip of the current tree (i5 5bd05f3f2) without
   re-burning a leg. This gives the team a **one-file team-facing** receipt
   of the whole family table with every identity gated.
2. Cross-round golden validations (r157 C1 live == r170 C1 A1, r163/r164/r165
   C2b live three-way, C2a/C2b byte-identical family 552,965 g).
3. A single CSV-shaped table that the team can grep / commit / reference /
   diff across rounds. The table is stable: every RAN number in it comes
   from a prior committed JSON receipt.

## Method

- `dkg_family_table.py` performs 1 pure-JSON read pass, 3 python arithmetic
  sections (family split / cross-leaf / aggregation), and 25 `check()` calls.
- Output captured into `r171_delta.r171` (RC 0, all 25 checks OK).
-  `git diff i5..HEAD` in the commit circumscribes the delta to a single new
  `poc/r171/` directory;  `circuits/ + crates/` is empty.

## UPSTREAM-PR: NONE (0 circuits/ + 0 crates/ source delta; receipts-only).