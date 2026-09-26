#!/usr/bin/env python3
P = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
A = 3641542188856621199
N = 8192
k = [0] * N
k[N - 2] = 1
k[N - 1] = (P - A) % P
acc = 0
for x in k:
    acc = (acc * A + x) % P
print("kernel check: v[N-2]=1, v[N-1]=-A  ->  pin(v) =", acc)
print("0 == exact kernel vector. acc-pin is a LINEAR functional (dim N-1 kernel)")
print("=> acc-pin ALONE does not bind a vector to a share; safe only WITH co-enforced per-coeff range+parity pins")