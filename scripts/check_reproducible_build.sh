#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_A="${BUILD_A:-build-repro-a}"
BUILD_B="${BUILD_B:-build-repro-b}"
CMAKE_GENERATOR="${CMAKE_GENERATOR:-Ninja}"

export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "${ROOT_DIR}" log -1 --pretty=%ct)}"

configure_and_build() {
  local dir="$1"
  cmake -S "${ROOT_DIR}" -B "${ROOT_DIR}/${dir}" -G "${CMAKE_GENERATOR}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_TESTING=OFF \
    -DSKIP_BPF_BUILD=ON \
    -DAEGIS_BPF_OBJ_DEFINE_PATH=/opt/aegisbpf/aegis.bpf.o
  cmake --build "${ROOT_DIR}/${dir}" -j"$(nproc)"
}

echo "building first artifact (${BUILD_A})"
configure_and_build "${BUILD_A}"
echo "building second artifact (${BUILD_B})"
configure_and_build "${BUILD_B}"

BIN_A="${ROOT_DIR}/${BUILD_A}/aegisbpf"
BIN_B="${ROOT_DIR}/${BUILD_B}/aegisbpf"
if [[ ! -f "${BIN_A}" || ! -f "${BIN_B}" ]]; then
  echo "missing build outputs for reproducibility check" >&2
  exit 1
fi

normalize_binary() {
  local src="$1"
  local dst="$2"
  cp "${src}" "${dst}"
  # Remove debug/build-id variance before checksum comparison.
  objcopy --strip-debug --remove-section .note.gnu.build-id "${dst}" 2>/dev/null || true
}

NORM_A="${ROOT_DIR}/${BUILD_A}/aegisbpf.norm"
NORM_B="${ROOT_DIR}/${BUILD_B}/aegisbpf.norm"
normalize_binary "${BIN_A}" "${NORM_A}"
normalize_binary "${BIN_B}" "${NORM_B}"

extract_stable_payload() {
  local src="$1"
  local out="$2"
  local tmp
  tmp="$(mktemp -d)"
  objcopy --dump-section .text="${tmp}/text.bin" "${src}" >/dev/null 2>&1 || true
  objcopy --dump-section .rodata="${tmp}/rodata.bin" "${src}" >/dev/null 2>&1 || true
  objcopy --dump-section .data.rel.ro="${tmp}/datarelro.bin" "${src}" >/dev/null 2>&1 || true
  : > "${out}"
  for part in "${tmp}/text.bin" "${tmp}/rodata.bin" "${tmp}/datarelro.bin"; do
    if [[ -f "${part}" ]]; then
      cat "${part}" >> "${out}"
    fi
  done
  rm -rf "${tmp}"
}

PAYLOAD_A="${ROOT_DIR}/${BUILD_A}/aegisbpf.payload"
PAYLOAD_B="${ROOT_DIR}/${BUILD_B}/aegisbpf.payload"
extract_stable_payload "${NORM_A}" "${PAYLOAD_A}"
extract_stable_payload "${NORM_B}" "${PAYLOAD_B}"

SHA_A="$(sha256sum "${PAYLOAD_A}" | awk '{print $1}')"
SHA_B="$(sha256sum "${PAYLOAD_B}" | awk '{print $1}')"

echo "sha256 build A: ${SHA_A}"
echo "sha256 build B: ${SHA_B}"

if [[ "${SHA_A}" != "${SHA_B}" ]]; then
  echo "reproducibility check failed: binaries differ" >&2
  exit 1
fi

echo "reproducibility check passed"
