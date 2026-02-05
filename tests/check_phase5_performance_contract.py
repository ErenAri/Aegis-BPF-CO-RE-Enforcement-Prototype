#!/usr/bin/env python3
"""Validate Phase-5 performance gates remain enforced."""

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
            "usage: check_phase5_performance_contract.py "
            "<perf.md> <phase5-evidence.md> <perf.yml> <perf_open_bench.sh> <perf_connect_bench.sh>",
            file=sys.stderr,
        )
        return 2

    perf_doc = Path(sys.argv[1])
    evidence_doc = Path(sys.argv[2])
    perf_workflow = Path(sys.argv[3])
    open_bench = Path(sys.argv[4])
    connect_bench = Path(sys.argv[5])

    errors: list[str] = []
    errors += require_text(
        perf_doc,
        [
            "p50_us",
            "p95_us",
            "p99_us",
            "loopback",
            "Noise controls",
            "event-drop ratio",
            "validate_perf_artifacts.py",
            "Perf artifact contract",
            "perf-evidence-report.md",
        ],
    )
    errors += require_text(
        evidence_doc,
        [
            "Phase 5 Performance Evidence",
            "perf.yml",
            "benchmark.yml",
            "soak.yml",
            "validate_perf_artifacts.py",
            "perf-evidence-report.md",
            "open_baseline.json",
            "connect_with_agent.json",
        ],
    )
    errors += require_text(
        perf_workflow,
        [
            "scripts/perf_connect_bench.sh",
            "scripts/perf_workload_suite.sh",
            "Upload perf profiles",
            "scripts/validate_perf_artifacts.py",
            "Validate perf artifact schema",
            "perf-evidence-report.md",
            "perf_workload.json",
            "kernel-info.txt",
            "cpu-info.txt",
        ],
    )
    errors += require_text(open_bench, ["p50_us", "p95_us", "p99_us"])
    errors += require_text(connect_bench, ["p50_us", "p95_us", "p99_us"])

    validator_script = Path(__file__).resolve().parents[1] / "scripts" / "validate_perf_artifacts.py"
    if not validator_script.is_file():
        errors.append(f"missing file: {validator_script}")

    if errors:
        for item in errors:
            print(item, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
