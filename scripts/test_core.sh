#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CMAKE_BIN="${CMAKE_BIN:-${ROOT_DIR}/.venv/bin/cmake}"
CTEST_BIN="${CTEST_BIN:-${ROOT_DIR}/.venv/bin/ctest}"
BUILD_DIR="${ROOT_DIR}/build/core"

if [[ ! -d "${BUILD_DIR}" ]]; then
  "${ROOT_DIR}/scripts/build_core.sh"
fi

"${CTEST_BIN}" --test-dir "${BUILD_DIR}" --output-on-failure
