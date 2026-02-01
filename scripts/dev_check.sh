#!/usr/bin/env bash
set -euo pipefail

BUILD_DIR="${BUILD_DIR:-build}"
CMAKE_FLAGS=${CMAKE_FLAGS:-"-DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON -DSKIP_BPF_BUILD=ON"}

cmake -S . -B "${BUILD_DIR}" ${CMAKE_FLAGS}
cmake --build "${BUILD_DIR}"
ctest --test-dir "${BUILD_DIR}" --output-on-failure
