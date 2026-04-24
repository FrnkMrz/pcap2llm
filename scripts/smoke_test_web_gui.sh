#!/usr/bin/env bash
set -euo pipefail

if [[ -x "./.venv/bin/python" ]]; then
  DEFAULT_PYTHON_BIN="./.venv/bin/python"
else
  DEFAULT_PYTHON_BIN="python"
fi

PYTHON_BIN="${PYTHON_BIN:-${DEFAULT_PYTHON_BIN}}"
HOST="${PCAP2LLM_WEB_HOST:-127.0.0.1}"
PORT="${PCAP2LLM_WEB_PORT:-8876}"
WORKDIR="${PCAP2LLM_WEB_WORKDIR:-$(mktemp -d "${TMPDIR:-/tmp}/pcap2llm-web-smoke.XXXXXX")}"
BASE_URL="http://${HOST}:${PORT}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/pcap2llm-web-smoke-client.XXXXXX")"
HEADERS_FILE="${TMP_DIR}/upload.headers"
UPLOAD_FILE="${TMP_DIR}/smoke_trace.pcapng"
SERVER_LOG="${TMP_DIR}/server.log"

cleanup() {
  if [[ -n "${SERVER_PID:-}" ]] && kill -0 "${SERVER_PID}" >/dev/null 2>&1; then
    kill "${SERVER_PID}" >/dev/null 2>&1 || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
  rm -rf "${TMP_DIR}"
  if [[ "${PCAP2LLM_WEB_WORKDIR:-}" == "" ]]; then
    rm -rf "${WORKDIR}"
  fi
}
trap cleanup EXIT

printf 'pcapng' > "${UPLOAD_FILE}"

PCAP2LLM_WEB_HOST="${HOST}" \
PCAP2LLM_WEB_PORT="${PORT}" \
PCAP2LLM_WEB_WORKDIR="${WORKDIR}" \
PYTHONPATH="${PYTHONPATH:-src}" \
"${PYTHON_BIN}" -m pcap2llm.web.app >"${SERVER_LOG}" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 30); do
  if curl -fsS "${BASE_URL}/" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

if ! curl -fsS "${BASE_URL}/" >/dev/null 2>&1; then
  echo "Smoke test failed: web server did not become ready at ${BASE_URL}." >&2
  cat "${SERVER_LOG}" >&2
  exit 1
fi

curl -fsS "${BASE_URL}/" >/dev/null
curl -fsS "${BASE_URL}/dashboard" >/dev/null
curl -fsS "${BASE_URL}/profiles" >/dev/null

curl -fsS -D "${HEADERS_FILE}" -o /dev/null \
  -F "capture=@${UPLOAD_FILE};type=application/octet-stream" \
  "${BASE_URL}/jobs"

JOB_LOCATION="$(awk '/^location:/ {print $2}' "${HEADERS_FILE}" | tr -d '\r')"
if [[ -z "${JOB_LOCATION}" ]]; then
  echo "Smoke test failed: upload did not return a Location header." >&2
  cat "${SERVER_LOG}" >&2
  exit 1
fi

curl -fsS "${BASE_URL}${JOB_LOCATION}" >/dev/null

echo "Smoke test passed: ${BASE_URL}${JOB_LOCATION}"
