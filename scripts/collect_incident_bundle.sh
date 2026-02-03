#!/usr/bin/env bash
set -euo pipefail

OUT_BASE="${1:-/tmp/aegisbpf-incident-$(date +%Y%m%d-%H%M%S)}"
OUT_DIR="${OUT_BASE}"
OUT_TAR="${OUT_BASE}.tar.gz"
AEGIS_BIN="${AEGIS_BIN:-aegisbpf}"

mkdir -p "${OUT_DIR}"

run_capture() {
  local name="$1"
  shift
  local out_file="${OUT_DIR}/${name}.txt"
  {
    echo "### command: $*"
    echo "### timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    "$@"
  } >"${out_file}" 2>&1 || true
}

echo "collecting incident evidence into ${OUT_DIR}"

run_capture "host_uname" uname -a
run_capture "host_id" id
run_capture "host_uptime" uptime
run_capture "host_mounts" mount
run_capture "host_processes" ps aux

if command -v "${AEGIS_BIN}" >/dev/null 2>&1; then
  run_capture "aegis_health_json" "${AEGIS_BIN}" health --json
  run_capture "aegis_stats" "${AEGIS_BIN}" stats
  run_capture "aegis_metrics" "${AEGIS_BIN}" metrics
  run_capture "aegis_policy_show" "${AEGIS_BIN}" policy show
  run_capture "aegis_policy_export" "${AEGIS_BIN}" policy export "${OUT_DIR}/policy.export"
  run_capture "aegis_block_list" "${AEGIS_BIN}" block list
  run_capture "aegis_allow_list" "${AEGIS_BIN}" allow list
  run_capture "aegis_survival_list" "${AEGIS_BIN}" survival list
  run_capture "aegis_network_deny_list" "${AEGIS_BIN}" network deny list
else
  echo "aegisbpf binary not found: ${AEGIS_BIN}" > "${OUT_DIR}/aegis_missing.txt"
fi

if command -v systemctl >/dev/null 2>&1; then
  run_capture "systemd_status" systemctl status aegisbpf
  run_capture "systemd_unit" systemctl cat aegisbpf
fi

if command -v journalctl >/dev/null 2>&1; then
  run_capture "journald_last_2h" journalctl -u aegisbpf --since "-2h" --no-pager
fi

if command -v dmesg >/dev/null 2>&1; then
  run_capture "dmesg_tail" dmesg -T | tail -n 400
fi

tar -czf "${OUT_TAR}" -C "$(dirname "${OUT_DIR}")" "$(basename "${OUT_DIR}")"
echo "incident evidence archive: ${OUT_TAR}"
