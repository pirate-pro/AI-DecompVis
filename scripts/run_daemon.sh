#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHONPATH="${ROOT_DIR}/core/aidecomp_py/python:${ROOT_DIR}/services/aidecomp_api:${ROOT_DIR}/services" \
  "${ROOT_DIR}/.venv/bin/python" -m aidecompd.main
