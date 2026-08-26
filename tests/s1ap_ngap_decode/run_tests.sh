#!/usr/bin/env bash
#
# run_tests.sh — regression tests for issue #132: S1AP/NGAP decode-result
# checking (F-BUG-201/210/213/218/219/220/221).
#
# Builds+installs the SDK to an isolated prefix, then compiles the test
# directly against the repo-tree headers of s1ap_common.h / ngap.h and links
# it with libmmt_tmobile so the ASN.1 decoders under test are exercised in
# their shipped configuration.
#
# Usage: tests/s1ap_ngap_decode/run_tests.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TEST_SRC="${SCRIPT_DIR}/test_s1ap_ngap_decode.c"

if [ -z "${MMT_PREFIX:-}" ]; then
    PREFIX="$(mktemp -d)"
    PREFIX_CREATED=1
else
    PREFIX="${MMT_PREFIX}"
fi
WORK="$(mktemp -d)"
BUILD_LOG="${WORK}/build.log"
if [ -n "${PREFIX_CREATED:-}" ]; then
    trap 'rm -rf "${WORK}" "${PREFIX}"' EXIT
else
    trap 'rm -rf "${WORK}"' EXIT
fi

CC="${CC:-gcc}"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 2)}"

# Optional SDK build profile forwarded by tests/run_all_tests.sh when the
# suites run under SANITIZE=asan|tsan (mirrors BUILD= in rules/common.mk).
SDK_MAKE_ARGS=()
if [ -n "${SDK_BUILD_PROFILE:-}" ]; then
    SDK_MAKE_ARGS=("BUILD=${SDK_BUILD_PROFILE}")
fi
SDK_MAKE_STR="${SDK_MAKE_ARGS[*]:-}"
set -- ${SDK_MAKE_STR}

echo "  repo root      : ${REPO_ROOT}"
echo "  install prefix : ${PREFIX}"

# --- 1. build + install the SDK to the isolated prefix ---------------------
echo "  [1/3] building + installing SDK ..."
make -C "${REPO_ROOT}/sdk" clean >/dev/null 2>&1 || true
if ! make -C "${REPO_ROOT}/sdk" "$@" -j"${JOBS}" MMT_BASE="${PREFIX}" >"${BUILD_LOG}" 2>&1; then
    echo "✗ SDK build failed — last lines:" >&2; tail -20 "${BUILD_LOG}" >&2; exit 1
fi
if ! make -C "${REPO_ROOT}/sdk" "$@" MMT_BASE="${PREFIX}" install >>"${BUILD_LOG}" 2>&1; then
    echo "✗ SDK install failed — last lines:" >&2; tail -20 "${BUILD_LOG}" >&2; exit 1
fi

INC="${PREFIX}/dpi/include"
LIB="${PREFIX}/dpi/lib"

# s1ap_common.h / ngap.h are internal headers (not installed), so the test
# compiles against the repo tree; the generated asn1c trees are never edited.
SRC_INC=(
    -I "${REPO_ROOT}/src/mmt_mobile/s1ap"
    -I "${REPO_ROOT}/src/mmt_mobile/ngap"
    -I "${REPO_ROOT}/src/mmt_mobile/asn1c/common"
    -I "${REPO_ROOT}/src/mmt_mobile/asn1c/s1ap"
    -I "${REPO_ROOT}/src/mmt_mobile/asn1c/ngap"
)

# --- 2. compile the test ---------------------------------------------------
# EXTRA_CFLAGS carries sanitizer/coverage instrumentation requested by
# tests/run_all_tests.sh; the binary stays in the suite dir so gcov data
# (.gcno/.gcda) survives for the coverage report.
echo "  [2/3] compiling test ..."
read -r -a extra_cflags <<< "${EXTRA_CFLAGS:-}"
${CC} "${extra_cflags[@]}" -O2 -Wall -o "${SCRIPT_DIR}/test_s1ap_ngap_decode" \
    "${TEST_SRC}" "${SRC_INC[@]}" \
    -I "${INC}" -L "${LIB}" -lmmt_tmobile -lmmt_core

# --- 3. run -----------------------------------------------------------------
echo "  [3/3] running test ..."
LD_LIBRARY_PATH="${LIB}:${LD_LIBRARY_PATH:-}" \
    "${SCRIPT_DIR}/test_s1ap_ngap_decode"

echo
echo "✓ S1AP/NGAP decode regression tests passed"
