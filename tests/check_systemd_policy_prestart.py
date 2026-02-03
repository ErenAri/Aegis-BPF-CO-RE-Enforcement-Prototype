#!/usr/bin/env python3
"""Validate that the systemd policy pre-start check is fail-closed."""

from pathlib import Path
import sys


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: check_systemd_policy_prestart.py <unit-file>", file=sys.stderr)
        return 2

    unit_path = Path(sys.argv[1])
    if not unit_path.is_file():
        print(f"unit file not found: {unit_path}", file=sys.stderr)
        return 1

    lines = unit_path.read_text(encoding="utf-8").splitlines()
    policy_lines = [
        line.strip()
        for line in lines
        if line.strip().startswith("ExecStartPre=") and "AEGIS_POLICY" in line
    ]

    if not policy_lines:
        print("missing AEGIS_POLICY ExecStartPre guard", file=sys.stderr)
        return 1

    apply_lines = [line for line in policy_lines if "policy apply" in line]
    if not apply_lines:
        print("policy guard does not call 'policy apply'", file=sys.stderr)
        return 1

    line = apply_lines[0]
    if "policy apply" not in line:
        print("policy guard does not call 'policy apply'", file=sys.stderr)
        return 1
    if "exit 1" not in line:
        print("policy guard is not fail-closed (no explicit exit 1)", file=sys.stderr)
        return 1
    if "|| true" in line:
        print("policy guard is fail-open (contains '|| true')", file=sys.stderr)
        return 1
    if "--require-signature" not in line:
        print("policy guard does not enforce --require-signature by default", file=sys.stderr)
        return 1
    if "AEGIS_REQUIRE_SIGNATURE" not in line:
        print("policy guard missing AEGIS_REQUIRE_SIGNATURE override", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
