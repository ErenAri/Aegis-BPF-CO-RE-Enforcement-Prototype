#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-build-key-drill}"
CMAKE_GENERATOR="${CMAKE_GENERATOR:-Ninja}"
SKIP_BPF_BUILD="${SKIP_BPF_BUILD:-ON}"
SUMMARY_OUT="${SUMMARY_OUT:-}"
TEST_REGEX="CmdPolicySignTest\\.CreatesSignedBundle|CmdPolicyApplySignedTest\\.RequireSignatureRejectsUnsignedPolicy|CmdPolicyApplySignedTest\\.RejectsRollbackBundleVersion|CmdKeysAddTest\\.RejectsWorldWritableKeyFile|KeyLifecycleTest\\.RotateAndRevokeTrustedSigningKeys"

echo "[1/3] Configure key-rotation drill build"
cmake -S "${ROOT_DIR}" -B "${ROOT_DIR}/${BUILD_DIR}" -G "${CMAKE_GENERATOR}" \
  -DCMAKE_BUILD_TYPE=Debug \
  -DBUILD_TESTING=ON \
  -DSKIP_BPF_BUILD="${SKIP_BPF_BUILD}"

echo "[2/3] Build tests"
cmake --build "${ROOT_DIR}/${BUILD_DIR}" -j"$(nproc)"

echo "[3/3] Run key-rotation contract tests"
ctest --test-dir "${ROOT_DIR}/${BUILD_DIR}" --output-on-failure \
  -R "${TEST_REGEX}"

if [ -n "${SUMMARY_OUT}" ]; then
  mkdir -p "$(dirname "${SUMMARY_OUT}")"
  cat > "${SUMMARY_OUT}" <<EOF
{
  "suite": "key_rotation_drill",
  "status": "passed",
  "ctest_regex": "${TEST_REGEX}",
  "timestamp_utc": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
}
EOF
  echo "Wrote summary: ${SUMMARY_OUT}"
fi

echo "Key rotation drill passed."
