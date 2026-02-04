#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-build-key-drill}"
CMAKE_GENERATOR="${CMAKE_GENERATOR:-Ninja}"

echo "[1/3] Configure key-rotation drill build"
cmake -S "${ROOT_DIR}" -B "${ROOT_DIR}/${BUILD_DIR}" -G "${CMAKE_GENERATOR}" \
  -DCMAKE_BUILD_TYPE=Debug \
  -DBUILD_TESTING=ON \
  -DSKIP_BPF_BUILD=ON

echo "[2/3] Build tests"
cmake --build "${ROOT_DIR}/${BUILD_DIR}" -j"$(nproc)"

echo "[3/3] Run key-rotation contract tests"
ctest --test-dir "${ROOT_DIR}/${BUILD_DIR}" --output-on-failure \
  -R "CmdPolicySignTest\\.CreatesSignedBundle|CmdPolicyApplySignedTest\\.RequireSignatureRejectsUnsignedPolicy|CmdPolicyApplySignedTest\\.RejectsRollbackBundleVersion|CmdKeysAddTest\\.RejectsWorldWritableKeyFile"

echo "Key rotation drill passed."
