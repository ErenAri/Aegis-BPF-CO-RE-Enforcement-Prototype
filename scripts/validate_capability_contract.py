#!/usr/bin/env python3
"""Validate documented Linux capability requirements match the systemd unit."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys


CAP_RE = re.compile(r"CAP_[A-Z0-9_]+")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Validate capability contract between SECURITY.md and "
            "packaging/systemd/aegisbpf.service"
        )
    )
    parser.add_argument("security_doc", type=Path)
    parser.add_argument("service_unit", type=Path)
    parser.add_argument(
        "--report",
        type=Path,
        help="Optional markdown report output path",
    )
    return parser.parse_args()


def read_text(path: Path) -> str:
    if not path.is_file():
        raise FileNotFoundError(f"missing file: {path}")
    return path.read_text(encoding="utf-8")


def parse_documented_caps(security_text: str) -> set[str]:
    if "### Minimum Privileges" not in security_text:
        raise ValueError("SECURITY.md missing 'Minimum Privileges' section")

    section = security_text.split("### Minimum Privileges", maxsplit=1)[1]
    section = section.split("### ", maxsplit=1)[0]
    return set(CAP_RE.findall(section))


def parse_service_caps(service_text: str, key: str) -> set[str]:
    marker = f"{key}="
    for line in service_text.splitlines():
        if not line.startswith(marker):
            continue
        values = line.split("=", maxsplit=1)[1].strip()
        return set(CAP_RE.findall(values))
    raise ValueError(f"service unit missing {marker}...")


def write_report(path: Path, documented: set[str], bounding: set[str], ambient: set[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    def fmt(values: set[str]) -> str:
        if not values:
            return "(none)"
        return "\n".join(f"- `{item}`" for item in sorted(values))

    report = "\n".join(
        [
            "# Capability Contract Report",
            "",
            "## Result",
            "PASS - documented and configured capabilities are aligned.",
            "",
            "## Documented capabilities (SECURITY.md)",
            fmt(documented),
            "",
            "## systemd CapabilityBoundingSet",
            fmt(bounding),
            "",
            "## systemd AmbientCapabilities",
            fmt(ambient),
            "",
        ]
    )
    path.write_text(report, encoding="utf-8")


def main() -> int:
    args = parse_args()
    errors: list[str] = []

    try:
        security_text = read_text(args.security_doc)
        service_text = read_text(args.service_unit)
    except FileNotFoundError as exc:
        print(exc, file=sys.stderr)
        return 1

    try:
        documented_caps = parse_documented_caps(security_text)
    except ValueError as exc:
        errors.append(str(exc))
        documented_caps = set()

    try:
        bounding_caps = parse_service_caps(service_text, "CapabilityBoundingSet")
        ambient_caps = parse_service_caps(service_text, "AmbientCapabilities")
    except ValueError as exc:
        errors.append(str(exc))
        bounding_caps = set()
        ambient_caps = set()

    if documented_caps and bounding_caps and documented_caps != bounding_caps:
        errors.append(
            "documented capabilities do not match CapabilityBoundingSet: "
            f"documented={sorted(documented_caps)} configured={sorted(bounding_caps)}"
        )

    if bounding_caps and ambient_caps and bounding_caps != ambient_caps:
        errors.append(
            "CapabilityBoundingSet does not match AmbientCapabilities: "
            f"bounding={sorted(bounding_caps)} ambient={sorted(ambient_caps)}"
        )

    if not documented_caps:
        errors.append("no capabilities found in SECURITY.md Minimum Privileges section")
    if not bounding_caps:
        errors.append("no capabilities found in CapabilityBoundingSet")
    if not ambient_caps:
        errors.append("no capabilities found in AmbientCapabilities")

    if errors:
        for err in errors:
            print(err, file=sys.stderr)
        return 1

    if args.report:
        write_report(args.report, documented_caps, bounding_caps, ambient_caps)

    print("Capability contract validated.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
