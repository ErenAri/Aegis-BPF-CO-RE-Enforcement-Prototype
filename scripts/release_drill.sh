#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-build-release-drill}"
ARTIFACT_DIR="${ARTIFACT_DIR:-${ROOT_DIR}/artifacts/release-drill}"
CMAKE_GENERATOR="${CMAKE_GENERATOR:-Ninja}"
SKIP_BPF_BUILD="${SKIP_BPF_BUILD:-OFF}"

require_cmd() {
    local cmd="$1"
    if ! command -v "${cmd}" >/dev/null 2>&1; then
        echo "missing required command: ${cmd}" >&2
        exit 1
    fi
}

require_cmd cmake
require_cmd cpack
require_cmd sha256sum
require_cmd python3

echo "[1/6] Configure release-drill build"
cmake -S "${ROOT_DIR}" -B "${ROOT_DIR}/${BUILD_DIR}" -G "${CMAKE_GENERATOR}" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX=/usr \
  -DBUILD_TESTING=OFF \
  -DSKIP_BPF_BUILD="${SKIP_BPF_BUILD}"

echo "[2/6] Build"
cmake --build "${ROOT_DIR}/${BUILD_DIR}" -j"$(nproc)"

echo "[3/6] Build packages"
(
    cd "${ROOT_DIR}/${BUILD_DIR}"
    cpack -G DEB
    cpack -G RPM
)

echo "[4/6] Collect artifacts"
mkdir -p "${ARTIFACT_DIR}"
cp "${ROOT_DIR}/${BUILD_DIR}"/aegisbpf "${ARTIFACT_DIR}/"
if [[ -f "${ROOT_DIR}/${BUILD_DIR}/aegis.bpf.o" ]]; then
    cp "${ROOT_DIR}/${BUILD_DIR}/aegis.bpf.o" "${ARTIFACT_DIR}/"
fi
if [[ -f "${ROOT_DIR}/${BUILD_DIR}/aegis.bpf.sha256" ]]; then
    cp "${ROOT_DIR}/${BUILD_DIR}/aegis.bpf.sha256" "${ARTIFACT_DIR}/"
fi
cp "${ROOT_DIR}/${BUILD_DIR}"/*.deb "${ARTIFACT_DIR}/" 2>/dev/null || true
cp "${ROOT_DIR}/${BUILD_DIR}"/*.rpm "${ARTIFACT_DIR}/" 2>/dev/null || true

tar_inputs=("aegisbpf")
if [[ -f "${ARTIFACT_DIR}/aegis.bpf.o" ]]; then
    tar_inputs+=("aegis.bpf.o")
fi
if [[ -f "${ARTIFACT_DIR}/aegis.bpf.sha256" ]]; then
    tar_inputs+=("aegis.bpf.sha256")
fi
tar -czf "${ARTIFACT_DIR}/aegisbpf-release-drill.tar.gz" -C "${ARTIFACT_DIR}" "${tar_inputs[@]}"

(
    cd "${ARTIFACT_DIR}"
    sha256sum *.tar.gz *.deb *.rpm 2>/dev/null >SHA256SUMS.txt || true
)

echo "[5/6] Package content checks"
if command -v dpkg-deb >/dev/null 2>&1; then
    for deb in "${ARTIFACT_DIR}"/*.deb; do
        [[ -e "${deb}" ]] || continue
        listing="$(dpkg-deb --contents "${deb}")"
        grep -q "usr/bin/aegisbpf$" <<<"${listing}" || {
            echo "missing /usr/bin/aegisbpf in ${deb}" >&2
            exit 1
        }
        grep -Eq "systemd/system/aegisbpf.service$" <<<"${listing}" || {
            echo "missing systemd unit in ${deb}" >&2
            exit 1
        }
    done
fi

if command -v rpm >/dev/null 2>&1; then
    for pkg in "${ARTIFACT_DIR}"/*.rpm; do
        [[ -e "${pkg}" ]] || continue
        listing="$(rpm -qpl "${pkg}")"
        grep -q "/usr/bin/aegisbpf$" <<<"${listing}" || {
            echo "missing /usr/bin/aegisbpf in ${pkg}" >&2
            exit 1
        }
        grep -Eq "systemd/system/aegisbpf.service$" <<<"${listing}" || {
            echo "missing systemd unit in ${pkg}" >&2
            exit 1
        }
    done
fi

echo "[6/6] Upgrade compatibility contract"
python3 "${ROOT_DIR}/tests/check_upgrade_compat.py" \
  "${ROOT_DIR}/${BUILD_DIR}/aegisbpf" \
  "${ROOT_DIR}/tests/fixtures/upgrade/policy_v1.conf" \
  "${ROOT_DIR}/tests/fixtures/upgrade/policy_v2.conf"

echo "Release drill passed. Artifacts: ${ARTIFACT_DIR}"
