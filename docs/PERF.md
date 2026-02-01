# Performance Harness

This repo includes a minimal open/close micro-benchmark to track regression.

## Usage

Baseline (no agent):
```
ITERATIONS=200000 FILE=/etc/hosts scripts/perf_open_bench.sh
```

With the agent running in audit mode:
```
WITH_AGENT=1 ITERATIONS=200000 FILE=/etc/hosts scripts/perf_open_bench.sh
```

`WITH_AGENT=1` requires root privileges.

Compare `us_per_op` between runs. Increase `ITERATIONS` for smoother results.

## Compare helper

Run both passes and report delta (fails if overhead exceeds `MAX_PCT`):

```
MAX_PCT=10 ITERATIONS=200000 FILE=/etc/hosts sudo scripts/perf_compare.sh
```

CI note: `.github/workflows/perf.yml` runs this check on a labeled self-hosted runner.

## JSON output

Use `FORMAT=json` and optionally `OUT=/path`:

```
FORMAT=json OUT=/tmp/perf.json ITERATIONS=200000 FILE=/etc/hosts scripts/perf_open_bench.sh
```
