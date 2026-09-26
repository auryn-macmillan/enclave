#!/usr/bin/env bash
set -u
B=/home/dev/interfld/poc/r133
for n in a0 a1 b0 b1 b2 b3 b4 b5 b6; do
  f=$B/${n}_gates.json
  [ -f "$f" ] || continue
  cs=$(grep -o '"cir