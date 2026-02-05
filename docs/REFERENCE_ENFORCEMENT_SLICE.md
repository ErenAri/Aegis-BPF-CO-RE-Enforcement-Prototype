# Reference Enforcement Slice

Version: 1.0 (2026-02-05)
Status: Decision-grade reference for v1 enforcement.

This document defines the single inode-first deny path that is treated as the
decision-grade reference. All enforcement expansions must keep this slice
passing across kernels and must not regress its semantics.

## Reference slice definition

- Deny a single inode via `aegisbpf block add <path>`
- Verify direct open/read is blocked
- Verify symlink and hardlink views of the same inode are blocked
- Verify a benign file remains readable
- Verify logs show the expected deny action and inode ID

## Canonical test

```
scripts/reference_enforcement_slice.sh
```

This script is executed in privileged e2e workflows and kernel matrix runs.

## Expansion rule

No enforcement scope expansion is allowed unless:
- the reference slice passes on all required kernels
- an independent review confirms no regression in semantics
