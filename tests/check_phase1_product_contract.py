#!/usr/bin/env python3
"""Validate Phase-1 product-contract evidence remains enforced."""

from __future__ import annotations

from pathlib import Path
import sys


def require_text(path: Path, needles: list[str]) -> list[str]:
    if not path.is_file():
        return [f"missing file: {path}"]
    text = path.read_text(encoding="utf-8")
    missing = [needle for needle in needles if needle not in text]
    return [f"{path}: missing '{item}'" for item in missing]


def main() -> int:
    if len(sys.argv) != 6:
        print(
            "usage: check_phase1_product_contract.py "
            "<threat_model.md> <policy_semantics.md> <maturity_program.md> "
            "<phase1_evidence.md> <readme.md>",
            file=sys.stderr,
        )
        return 2

    threat_model = Path(sys.argv[1])
    policy_semantics = Path(sys.argv[2])
    maturity_program = Path(sys.argv[3])
    phase1_evidence = Path(sys.argv[4])
    readme = Path(sys.argv[5])

    errors: list[str] = []

    errors += require_text(
        threat_model,
        [
            "### Syscall path coverage boundaries",
            "### Filesystem caveats",
            "### Container and orchestration caveats",
            "User namespaces",
            "Privileged Kubernetes pods",
            "### Accepted vs non-accepted bypasses",
        ],
    )
    errors += require_text(
        policy_semantics,
        [
            "## Deterministic precedence and conflict resolution",
            "## Namespace and mount consistency contract",
            "allow_cgroup",
            "inode reuse",
            "bind mounts",
        ],
    )
    errors += require_text(
        maturity_program,
        [
            "## Phase 1: Product contract",
            "Threat model, non-goals, and bypass acceptance list",
            "Policy semantics spec defines precedence",
        ],
    )
    errors += require_text(
        phase1_evidence,
        [
            "Phase 1 Product Contract Evidence",
            "docs/THREAT_MODEL.md",
            "docs/POLICY_SEMANTICS.md",
            "tests/check_phase1_product_contract.py",
            "phase1_product_contract",
        ],
    )
    errors += require_text(
        readme,
        [
            "docs/THREAT_MODEL.md",
            "docs/POLICY_SEMANTICS.md",
            "docs/MATURITY_PROGRAM.md",
            "docs/PHASE1_PRODUCT_CONTRACT_EVIDENCE.md",
            "Claim Taxonomy",
            "`ENFORCED`",
            "`AUDITED`",
            "`PLANNED`",
        ],
    )

    if errors:
        for item in errors:
            print(item, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

