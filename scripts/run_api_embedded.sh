#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AIDECOMP_RUNTIME_MODE=embedded \
PYTHONPATH="${ROOT_DIR}/core/aidecomp_py/python:${ROOT_DIR}/services/aidecomp_api:${ROOT_DIR}/services" \
  "${ROOT_DIR}/.venv/bin/uvicorn" aidecomp_api.main:app --app-dir "${ROOT_DIR}/services/aidecomp_api" --host 127.0.0.1 --port 8000
