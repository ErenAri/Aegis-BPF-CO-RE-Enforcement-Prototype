#!/usr/bin/env python3
"""Validate support-policy doc has required production sections."""

from __future__ import annotations

from pathlib import Path
import sys


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: check_support_policy.py <support-policy.md>", file=sys.stderr)
        return 2

    text = Path(sys.argv[1]).read_text(encoding="utf-8")

    required_snippets = [
        "## Release Model",
        "## Support Windows",
        "N-1",
        "## Compatibility Commitments",
        "## Deprecation Policy",
        "two minor releases",
        "## End-of-Life (EOL)",
    ]

    missing = [item for item in required_snippets if item not in text]
    if missing:
        print("support policy missing required content:", file=sys.stderr)
        for item in missing:
            print(f"  - {item}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
