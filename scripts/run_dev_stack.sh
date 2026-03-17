#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
API_HOST="${API_HOST:-127.0.0.1}"
WEB_HOST="${WEB_HOST:-127.0.0.1}"
API_PORT="${API_PORT:-8000}"
WEB_PORT="${WEB_PORT:-5173}"

is_port_in_use() {
  local port="$1"
  ss -ltn "( sport = :${port} )" 2>/dev/null | grep -q ":${port}"
}

pick_free_port() {
  local port="$1"
  while is_port_in_use "${port}"; do
    port=$((port + 1))
  done
  echo "${port}"
}

API_PORT="$(pick_free_port "${API_PORT}")"
WEB_PORT="$(pick_free_port "${WEB_PORT}")"

cleanup() {
  if [[ -n "${API_PID:-}" ]] && kill -0 "${API_PID}" 2>/dev/null; then
    kill "${API_PID}" 2>/dev/null || true
  fi
  if [[ -n "${WEB_PID:-}" ]] && kill -0 "${WEB_PID}" 2>/dev/null; then
    kill "${WEB_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

echo "[AI-DecompVis] backend: http://${API_HOST}:${API_PORT}"
echo "[AI-DecompVis] frontend: http://${WEB_HOST}:${WEB_PORT}"
echo "[AI-DecompVis] press Ctrl+C to stop both services"

(
  cd "${ROOT_DIR}"
  PYTHONPATH=core/aidecomp_py/python:services/aidecomp_api:services \
    "${ROOT_DIR}/.venv/bin/uvicorn" aidecomp_api.main:app \
    --app-dir "${ROOT_DIR}/services/aidecomp_api" \
    --host "${API_HOST}" \
    --port "${API_PORT}" \
    --log-level info
) &
API_PID=$!

(
  cd "${ROOT_DIR}/apps/web"
  VITE_PROXY_TARGET="http://${API_HOST}:${API_PORT}" npm run dev -- --host "${WEB_HOST}" --port "${WEB_PORT}"
) &
WEB_PID=$!

wait -n "${API_PID}" "${WEB_PID}"
