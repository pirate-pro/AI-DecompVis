#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-${ROOT_DIR}/.venv/bin/python}"
CMAKE_BIN="${CMAKE_BIN:-${ROOT_DIR}/.venv/bin/cmake}"
BUILD_DIR="${ROOT_DIR}/build/core"

"${CMAKE_BIN}" -S "${ROOT_DIR}/core" -B "${BUILD_DIR}" \
  -DCMAKE_BUILD_TYPE=Release \
  -DPython3_EXECUTABLE="${PYTHON_BIN}" \
  -DAIDECOMP_BUILD_PYBIND=ON

"${CMAKE_BIN}" --build "${BUILD_DIR}" -j
