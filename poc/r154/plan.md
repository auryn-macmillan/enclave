# r154 — C6 I14 re-measure at the PRODUCTION shape (N=19/T=9/H=14, secure-8192)

**One idea.** r152f-c0 / r152d / r152c / r152b / r151b / r151 all RAN at *minimum* committee
(N=3/T=1/H=2) on secure-8192. The production gateway config is **small** committee (N=19/T=9/
H=14, `circuits/lib/src/configs/committee/small/mod.nr`) on secure-8192. The owner's own
scope-re-authorization call on the r154 in-tree C6 ship (per the 2026-10-03 POKE, now per-diff
re-auth per r152f framing) is made against the *production* N/T/H shape. r153's RAN (-415,111 g
= -15.959% of the new-base C6 leaf at N=3) is the same family measured at a different R shape.
The load-bearing question the owner will ask is "does the I14 cut still live at production
N=19/T=9/H=14 penalty, and how big is it?" — nobody has RAN the N=19 small-committee C6 leaf
on this box since the 2026-09-11 re-provision (8c/32 GiB, N=19 RAN-eligible per the HARDWARE
note; box-there but not actually exercised for this leaf yet).

**Shape of the RAN (identical class to r115/r150/r153 shadow-NOP):**
- 2 legs in /tmp/r151b (detached @ c98b0d1ca, PORC 0 pre+post), prepared by flipping the
  committee template: `configs/committee/active.nr` minimum -> small (N=19/T=9/H=14; parity
  matrix small + secure) and `configs/default/mod.nr` insecure-512 -> secure-8192.
- V0 = unblunt C6 I14, secure-8192/small, N=19/T=9/H=14, one fresh `nargo compile` pass.
- V1 = V0 + the r153 5-site I14 shadow patch (drop ct0limbs/ct1limbs from generate_challenge,
  put c.ct_commitment into the sponge domain twice instead; 5-site form: 3 r115-original
  generate_challenge call-sites + 2 sites added inside the r115 norm-circuit shadow-prefix
  test body, per r153 3-site leg capture + r153 V1-using leg = holds at the N=19 parity as well,
  anchors are added φ-region minimal and do not touch N-parties).
  In-tree source is restored byte-exact after V1; only config flip + restored json remain.
- Measurement set per leg: gates / ACIR / wall / peak RSS / FRESH_SHA256 (against in-tree
  restored SHAs for preservation self-check).
- Box wall if OOMs 32 GiB: log the exact leg that died, cite the peak, write the box-2
  ([/-taskset -c 0-7]) DRAFT command and the remote RAN line in LOG.md; DRAFT-close the
  hypothesis-confirmation leg even if the RAN cannot run on-box (box-ceiling class per r150/r151).

**What it answers (before the in-tree edit can be authorized):**
- Whether -415,111 g (or its ratio) holds at production N/T/H. If R-an = distinct gates, the
  in-tree ship's effective DKG-hours cut will differ from r153's 54.35 s wall (which was
  4-core-pinned @N=3); update the LOB-AN estimate in STATE.md's PRIORITIES (item (5)) to the
  production-shape number the owner actually sees when they compile the next release's
  secure-8192/small audit.
- MEM ceiling on-box vs the r105–r109 class at N=19. If the N=19 C6 leaf needs > 32 GiB,
  re-establish the box-2 ask (>= 64 GiB, item (6)) with a live OOM record on this re-provisioned
  box — which 3 rounds ago still had the old 7.8 GiB ceiling.

**Tree hygiene:** cycles 0 (same pre-proc-pin rationale); configs DEF/ACT byte-exact pre+post;
in-tree /right/ shield shape_decryption bytes -- down to 2324. Every single DISTINCT leg's
output stays DRAFT-runnable deterministically via /tmp/r154 recipe files + site lockable system
unit.