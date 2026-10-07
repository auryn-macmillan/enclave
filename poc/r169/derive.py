import json,glob
def dg(p):
  d=json.load(open(p))
  g=sum(f.get("circuit_size",0) for f in d.get("functions",[]))
  a=sum(f.get("acir_opcodes",0) for f in d.get("functions",[]))
  return g,a
E,dGe=dg("poc/r169/r169E_live_gates.json")
S,dGs=dg("poc/r169/r169S_no_sponge_gates.json")
J,dj=dg("poc/r166/Jall_gates.json")
print("E   = E  g/ACIR:",E,dGe)
print("S   = S  g/ACIR:",S,dGs)
print("Jall= J0+1+2-sum-style R166 RAN: g/ACIR:",J,dj)
X=E-S
dX=dGe-dGs
print("X=E-S:",X, dX,"density:",X/dX)
V1=E-J
nv=S-J
print("V1 (E-Jall)      =",V1)
print("vS (S-Jall)      =",nv)
print("V1 - vS          =",V1-nv, " (= X by identity)", "(= X-ok)" if V1-nv==X else "MISMATCH")
print("r167 block       = 138420  (density 19.0007)")
print("r168 assert      = 96255   (density 1.9583)")
print("X (this round)   =",X,"(density %.4f)"%(X/dX))
print("X - block        =",X-138420)
print("X ~ block? within 2%%:", abs(X-138420) <= 0.02*138420)