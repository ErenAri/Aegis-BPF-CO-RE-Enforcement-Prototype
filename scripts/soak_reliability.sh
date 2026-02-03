#!/usr/bin/env bash
set -euo pipefail

AEGIS_BIN="${AEGIS_BIN:-./build/aegisbpf}"
DURATION_SECONDS="${DURATION_SECONDS:-300}"
WORKERS="${WORKERS:-4}"
POLL_SECONDS="${POLL_SECONDS:-5}"
MAX_RINGBUF_DROPS="${MAX_RINGBUF_DROPS:-1000}"
MAX_RSS_GROWTH_KB="${MAX_RSS_GROWTH_KB:-65536}"
RINGBUF_BYTES="${RINGBUF_BYTES:-16777216}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "soak_reliability.sh must run as root" >&2
  exit 1
fi

if [[ ! -x "${AEGIS_BIN}" ]]; then
  echo "aegisbpf binary not found or not executable: ${AEGIS_BIN}" >&2
  exit 1
fi

if ! [[ "${DURATION_SECONDS}" =~ ^[0-9]+$ && "${POLL_SECONDS}" =~ ^[0-9]+$ && "${WORKERS}" =~ ^[0-9]+$ ]]; then
  echo "DURATION_SECONDS, POLL_SECONDS, and WORKERS must be numeric" >&2
  exit 1
fi

if ! [[ "${MAX_RINGBUF_DROPS}" =~ ^[0-9]+$ && "${MAX_RSS_GROWTH_KB}" =~ ^[0-9]+$ ]]; then
  echo "MAX_RINGBUF_DROPS and MAX_RSS_GROWTH_KB must be numeric" >&2
  exit 1
fi

LOG_DIR="$(mktemp -d /tmp/aegisbpf-soak-XXXXXX)"
DAEMON_LOG="${LOG_DIR}/daemon.log"
WORKLOAD_LOG="${LOG_DIR}/workload.log"
WORKER_PIDS=()
DAEMON_PID=""

cleanup() {
  set +e
  for wp in "${WORKER_PIDS[@]:-}"; do
    kill "${wp}" >/dev/null 2>&1
  done
  if [[ -n "${DAEMON_PID}" ]]; then
    kill -INT "${DAEMON_PID}" >/dev/null 2>&1
    wait "${DAEMON_PID}" >/dev/null 2>&1
  fi
  set -e
}
trap cleanup EXIT

echo "starting daemon for soak test (duration=${DURATION_SECONDS}s workers=${WORKERS})"
"${AEGIS_BIN}" run --audit --ringbuf-bytes="${RINGBUF_BYTES}" >"${DAEMON_LOG}" 2>&1 &
DAEMON_PID=$!
sleep 2

if ! kill -0 "${DAEMON_PID}" >/dev/null 2>&1; then
  echo "daemon failed to start" >&2
  cat "${DAEMON_LOG}" >&2 || true
  exit 1
fi

for _ in $(seq 1 "${WORKERS}"); do
  (
    while kill -0 "${DAEMON_PID}" >/dev/null 2>&1; do
      cat /etc/hosts >/dev/null 2>&1 || true
    done
  ) >>"${WORKLOAD_LOG}" 2>&1 &
  WORKER_PIDS+=("$!")
done

read_rss_kb() {
  awk '/VmRSS:/ { print $2; found=1 } END { if (!found) print 0 }' "/proc/${DAEMON_PID}/status"
}

INITIAL_RSS="$(read_rss_kb)"
MAX_RSS="${INITIAL_RSS}"
MAX_DROPS=0
END_TS=$((SECONDS + DURATION_SECONDS))

echo "initial RSS: ${INITIAL_RSS} kB"

while [[ ${SECONDS} -lt ${END_TS} ]]; do
  if ! kill -0 "${DAEMON_PID}" >/dev/null 2>&1; then
    echo "daemon exited early during soak" >&2
    cat "${DAEMON_LOG}" >&2 || true
    exit 1
  fi

  RSS="$(read_rss_kb)"
  if [[ "${RSS}" -gt "${MAX_RSS}" ]]; then
    MAX_RSS="${RSS}"
  fi

  METRICS="$("${AEGIS_BIN}" metrics 2>/dev/null || true)"
  DROPS="$(awk '$1=="aegisbpf_ringbuf_drops_total" {print $2; exit}' <<<"${METRICS}")"
  DROPS="${DROPS:-0}"
  if [[ "${DROPS}" =~ ^[0-9]+$ && "${DROPS}" -gt "${MAX_DROPS}" ]]; then
    MAX_DROPS="${DROPS}"
  fi

  sleep "${POLL_SECONDS}"
done

RSS_GROWTH=$((MAX_RSS - INITIAL_RSS))

echo "max RSS: ${MAX_RSS} kB (growth=${RSS_GROWTH} kB)"
echo "max ringbuf drops: ${MAX_DROPS}"

if [[ "${RSS_GROWTH}" -gt "${MAX_RSS_GROWTH_KB}" ]]; then
  echo "RSS growth exceeded threshold (${RSS_GROWTH} > ${MAX_RSS_GROWTH_KB})" >&2
  exit 1
fi

if [[ "${MAX_DROPS}" -gt "${MAX_RINGBUF_DROPS}" ]]; then
  echo "ringbuf drops exceeded threshold (${MAX_DROPS} > ${MAX_RINGBUF_DROPS})" >&2
  exit 1
fi

echo "soak reliability checks passed"
