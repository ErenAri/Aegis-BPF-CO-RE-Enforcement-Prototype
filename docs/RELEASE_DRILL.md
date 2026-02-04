# Release Drill Runbook

Run this before cutting a real release tag.

## What it validates

- Release build and packaging (`.deb`, `.rpm`, tarball)
- Artifact checksum generation
- Package content sanity (`/usr/bin/aegisbpf`, systemd unit presence)
- Upgrade compatibility contract check

## Command

```bash
scripts/release_drill.sh
```

Useful overrides:

```bash
BUILD_DIR=build-release-drill \
ARTIFACT_DIR=artifacts/release-drill \
SKIP_BPF_BUILD=ON \
scripts/release_drill.sh
```

## CI automation

The drill is automated by `.github/workflows/release-drill.yml`.

## Evidence to keep

- Workflow/job URL
- `SHA256SUMS.txt`
- Artifact inventory
- Upgrade compatibility check output
