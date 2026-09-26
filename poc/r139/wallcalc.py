import sys
a=float(open(sys.argv[1]).read().strip()); b=float(open(sys.argv[2]).read().strip())
print(f"T0={a:.2f}"); print(f"T1={b:.2f}"); print(f"WALL_SECONDS={b-a:.2f}")
