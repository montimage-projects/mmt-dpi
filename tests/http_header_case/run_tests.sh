#!/usr/bin/env bash
#
# run_tests.sh — regression harness for issue #24 (M8):
#   "Make HTTP header matching case-insensitive".
#
# It:
#   1. builds + installs the SDK to an isolated prefix (does NOT touch /opt/mmt
#      or any system install),
#   2. compiles test_http_header_case.c against that prefix,
#   3. runs it from a working dir that has a CWD-relative "plugins/" symlink to
#      the freshly built protocol plugins (the SDK loads plugins from
#      ./plugins first — see plugins_engine.c), so the test exercises THIS
#      branch's parser, not a pre-installed one,
#   4. asserts canonical / lower / mixed-case "Host:" headers all drive the
#      host-based FACEBOOK classification.
#
# Usage: tests/http_header_case/run_tests.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TEST_SRC="${SCRIPT_DIR}/test_http_header_case.c"

PREFIX="${MMT_PREFIX:-$(mktemp -d)}"
WORK="$(mktemp -d)"
BUILD_LOG="${WORK}/build.log"
trap 'rm -rf "${WORK}"' EXIT

CC="${CC:-gcc}"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 2)}"

echo "  repo root      : ${REPO_ROOT}"
echo "  install prefix : ${PREFIX}"

# --- 1. build + install the SDK to the isolated prefix ---------------------
echo "  [1/3] building + installing SDK ..."
make -C "${REPO_ROOT}/sdk" clean >/dev/null 2>&1 || true
if ! make -C "${REPO_ROOT}/sdk" -j"${JOBS}" MMT_BASE="${PREFIX}" >"${BUILD_LOG}" 2>&1; then
    echo "✗ SDK build failed — last lines:" >&2; tail -20 "${BUILD_LOG}" >&2; exit 1
fi
if ! make -C "${REPO_ROOT}/sdk" MMT_BASE="${PREFIX}" install >>"${BUILD_LOG}" 2>&1; then
    echo "✗ SDK install failed — last lines:" >&2; tail -20 "${BUILD_LOG}" >&2; exit 1
fi

INC="${PREFIX}/dpi/include"
LIB="${PREFIX}/dpi/lib"
PLUGINS="${PREFIX}/plugins"
if [ ! -d "${PLUGINS}" ]; then
    echo "✗ plugins dir not found after install: ${PLUGINS}" >&2; exit 1
fi

# --- 2. compile the test ---------------------------------------------------
echo "  [2/3] compiling test ..."
${CC} -O2 -Wall -o "${WORK}/test_http_header_case" \
    "${TEST_SRC}" -I "${INC}" -L "${LIB}" -lmmt_core -ldl

# --- 3. run with CWD-relative plugins/ pointing at the built plugins -------
echo "  [3/3] running test ..."
ln -s "${PLUGINS}" "${WORK}/plugins"
( cd "${WORK}" && LD_LIBRARY_PATH="${LIB}:${LD_LIBRARY_PATH:-}" \
    ./test_http_header_case )

echo
echo "✓ HTTP header case-insensitivity regression test passed"
