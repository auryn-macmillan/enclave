# r152d - C2a + C2b re-anchor + C4 solo re-anchor on NEW upstream base c98b0d1ca (#1999).
# Sibling legs of r152b (C3) and r152c (C1). Working branch i5/dkg-research evidence base
# c98b0d1ca (rebase onto origin/main RED-BLOCKED at commit 13/93, share_encryption.nr, since
# r152b; NOT forced per protocol). Detached worktree R=/tmp/r151b (porcelain 0 pre+post).
# 5-stack plan (adjustable by budget; EXACT rule = "C2a + C2b re-anchor + C4-presence
# reconfirmation"; the per-limb/cross-check-style C leg below is an OPTIONAL r145-class
# extension only if A/B/C2b close cleanly and wall buffer remains):
#   A  : unblunt C2a re-anchor (sk_... package, 2 circuits); C2b re-anchor (e_sm package)
#        mapped twin per old-base r145/r146.
#   B  : C2a execution in share_computation.nr, 1st check_range_bounds call site NOP
#        -> C2a family price.
#   C  : C2b execution in share_computation.nr, 2nd check_range_bounds call site NOP
#        -> C2b family price (<- this leg SUPPLANTED by original plan; see note below).
#   C4 : unblunt share_decryption solo re-anchor -> r150 C4A sibling price at new base
#        (old r150 already RAN-killed the C4 range family in THIS worktree; the re-anchor
#        here is a one-leg closure for the new-base table, not a second kill I think it
#        hopeless).
# Plus OPTIONAL (only if wall budget remains): per-limb vs flat split on the C2a/C2b family
# (r146/r147-shaped per-site NOP of the per-coeff/payment-plane loop bodies inside the
# share_computation call sites).