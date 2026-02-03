#!/usr/bin/env python3
"""Validate N-1 -> N policy compatibility behavior."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def run_cmd(args: list[str], env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        env=env,
        check=False,
        text=True,
        capture_output=True,
    )


def expect_ok(proc: subprocess.CompletedProcess[str], what: str) -> None:
    if proc.returncode == 0:
        return
    print(f"{what} failed with rc={proc.returncode}", file=sys.stderr)
    if proc.stdout:
        print("stdout:", file=sys.stderr)
        print(proc.stdout, file=sys.stderr)
    if proc.stderr:
        print("stderr:", file=sys.stderr)
        print(proc.stderr, file=sys.stderr)
    raise SystemExit(1)


def main() -> int:
    if len(sys.argv) != 4:
        print(
            "usage: check_upgrade_compat.py <aegisbpf-bin> <policy-v1> <policy-v2>",
            file=sys.stderr,
        )
        return 2

    binary = Path(sys.argv[1])
    policy_v1 = Path(sys.argv[2])
    policy_v2 = Path(sys.argv[3])

    if not binary.is_file():
        print(f"binary not found: {binary}", file=sys.stderr)
        return 1
    if not policy_v1.is_file():
        print(f"policy fixture not found: {policy_v1}", file=sys.stderr)
        return 1
    if not policy_v2.is_file():
        print(f"policy fixture not found: {policy_v2}", file=sys.stderr)
        return 1

    # N-1 compatibility: legacy (v1) policy must still validate/lint on current binary.
    expect_ok(run_cmd([str(binary), "policy", "lint", str(policy_v1)]), "policy lint v1")
    expect_ok(run_cmd([str(binary), "policy", "validate", str(policy_v1)]), "policy validate v1")

    # Current format must also validate/lint.
    expect_ok(run_cmd([str(binary), "policy", "lint", str(policy_v2)]), "policy lint v2")
    expect_ok(run_cmd([str(binary), "policy", "validate", str(policy_v2)]), "policy validate v2")

    # Simulate N-1 state files being read by current binary.
    with tempfile.TemporaryDirectory(prefix="aegisbpf-upgrade-compat-") as tmp:
        tmp_path = Path(tmp)
        applied_path = tmp_path / "policy.applied"
        hash_path = tmp_path / "policy.applied.hash"

        shutil.copyfile(policy_v1, applied_path)
        hash_path.write_text("f" * 64 + "\n", encoding="utf-8")

        env = os.environ.copy()
        env["AEGIS_POLICY_APPLIED_PATH"] = str(applied_path)
        env["AEGIS_POLICY_APPLIED_HASH_PATH"] = str(hash_path)

        show_v1 = run_cmd([str(binary), "policy", "show"], env=env)
        expect_ok(show_v1, "policy show v1")
        if "version=1" not in show_v1.stdout:
            print("policy show output missing version=1", file=sys.stderr)
            return 1

        shutil.copyfile(policy_v2, applied_path)
        show_v2 = run_cmd([str(binary), "policy", "show"], env=env)
        expect_ok(show_v2, "policy show v2")
        if "version=2" not in show_v2.stdout:
            print("policy show output missing version=2", file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
