# Phase 1 Product Contract Evidence

This page is the evidence bundle for **Phase 1 (Product contract)** in
`docs/MATURITY_PROGRAM.md`.

## Contract statement

Flagship guarantee (Phase 0 freeze):

> AegisBPF blocks unauthorized file opens/reads using inode-first enforcement
> for selected workloads (cgroup-targeted), with safe rollback and auditable
> signed policy provenance.

Primary references:
- `docs/MATURITY_PROGRAM.md` (golden contract + claim taxonomy)
- `docs/THREAT_MODEL.md` (attacker model, trust boundaries, blind spots)
- `docs/POLICY_SEMANTICS.md` (precedence + edge-case semantics)

## Threat-model evidence

`docs/THREAT_MODEL.md` explicitly defines:
- syscall path coverage boundaries
- filesystem caveats (including OverlayFS and bind mounts)
- container/orchestration caveats (including user namespaces and privileged
  Kubernetes pods)
- accepted vs non-accepted bypass controls

## Policy-semantics evidence

`docs/POLICY_SEMANTICS.md` explicitly defines:
- deterministic precedence and conflict resolution
- inode-first enforcement behavior
- namespace and mount consistency contract
- edge-case behavior (symlink/rename/hardlink/bind mount/inode reuse)

## Contract enforcement in CI

Phase-1 documentation/contract drift is guarded by:
- `tests/check_phase1_product_contract.py`
- CTest target: `phase1_product_contract`

The gate fails if threat-model and semantics sections required for the flagship
contract are removed or renamed.

