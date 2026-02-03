#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-build-release-readiness}"
CMAKE_GENERATOR="${CMAKE_GENERATOR:-Ninja}"

echo "[1/5] Configure release-readiness build"
cmake -S "${ROOT_DIR}" -B "${ROOT_DIR}/${BUILD_DIR}" -G "${CMAKE_GENERATOR}" \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DBUILD_TESTING=ON \
  -DSKIP_BPF_BUILD=ON

echo "[2/5] Build"
cmake --build "${ROOT_DIR}/${BUILD_DIR}" -j"$(nproc)"

echo "[3/5] Test"
ctest --test-dir "${ROOT_DIR}/${BUILD_DIR}" --output-on-failure --timeout 180

echo "[4/5] Contract checks"
python3 "${ROOT_DIR}/scripts/validate_event_schema.py" \
  --schema "${ROOT_DIR}/config/event-schema.json" \
  --samples "${ROOT_DIR}/tests/event_samples"
python3 "${ROOT_DIR}/tests/check_systemd_policy_prestart.py" \
  "${ROOT_DIR}/packaging/systemd/aegisbpf.service"
python3 "${ROOT_DIR}/tests/check_metrics_contract.py" \
  "${ROOT_DIR}/src/commands_monitoring.cpp" \
  "${ROOT_DIR}/config/prometheus/alerts.yml" \
  "${ROOT_DIR}/config/grafana/dashboard.json" \
  "${ROOT_DIR}/docs/man/aegisbpf.1.md"
python3 "${ROOT_DIR}/tests/check_slo_contract.py" \
  "${ROOT_DIR}/config/prometheus/alerts.yml" \
  "${ROOT_DIR}/docs/PRODUCT.md"
python3 "${ROOT_DIR}/tests/check_support_policy.py" \
  "${ROOT_DIR}/docs/SUPPORT_POLICY.md"
python3 "${ROOT_DIR}/tests/check_upgrade_compat.py" \
  "${ROOT_DIR}/${BUILD_DIR}/aegisbpf" \
  "${ROOT_DIR}/tests/fixtures/upgrade/policy_v1.conf" \
  "${ROOT_DIR}/tests/fixtures/upgrade/policy_v2.conf"

echo "[5/5] CLI parser sanity"
if "${ROOT_DIR}/${BUILD_DIR}/aegisbpf" metrics --invalid >/dev/null 2>&1; then
  echo "expected 'metrics --invalid' to fail" >&2
  exit 1
fi
if "${ROOT_DIR}/${BUILD_DIR}/aegisbpf" health --json --unknown >/dev/null 2>&1; then
  echo "expected 'health --json --unknown' to fail" >&2
  exit 1
fi
if "${ROOT_DIR}/${BUILD_DIR}/aegisbpf" network deny add --ip 192.0.2.1 --cidr 10.0.0.0/8 >/dev/null 2>&1; then
  echo "expected conflicting network selectors to fail" >&2
  exit 1
fi

echo "Release readiness checks passed."
