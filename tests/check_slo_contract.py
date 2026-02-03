#!/usr/bin/env python3
"""Ensure alerting rules and documented SLO targets stay aligned."""

from __future__ import annotations

from pathlib import Path
import re
import sys


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: check_slo_contract.py <alerts.yml> <product.md>", file=sys.stderr)
        return 2

    alerts_text = Path(sys.argv[1]).read_text(encoding="utf-8")
    product_text = Path(sys.argv[2]).read_text(encoding="utf-8")

    required_alerts = {
        "AegisBPFRingbufDrops",
        "AegisBPFEventLossSLOViolation",
        "AegisBPFMetricsStale",
        "AegisBPFNetworkRingbufDrops",
        "AegisBPFNetworkEventLossSLOViolation",
    }

    present_alerts = set(re.findall(r"^\s*-\s*alert:\s*([A-Za-z0-9_]+)\s*$", alerts_text, flags=re.M))
    missing_alerts = sorted(required_alerts - present_alerts)
    if missing_alerts:
        print("missing required SLO/observability alerts:", file=sys.stderr)
        for name in missing_alerts:
            print(f"  - {name}", file=sys.stderr)
        return 1

    # Ensure event-loss SLO is documented as 0.1%.
    if "Event loss (ring buffer drops): <0.1%" not in product_text:
        print("product SLO doc missing event loss target (<0.1%)", file=sys.stderr)
        return 1

    # Ensure stale-metrics SLO target is documented.
    if "no stale counters for >30m" not in product_text:
        print("product SLO doc missing stale counter target (>30m)", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
