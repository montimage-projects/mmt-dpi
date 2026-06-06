#!/usr/bin/env bash
#
# run_bitmask_oob_test.sh — build + run the protocol-bitmask OOB unit test
# (issues #51 and #52, Phase 2 memory-safety).
#
# The bitmask struct + macros live in the internal header
# src/mmt_tcpip/lib/mmt_tcpip_internal_defs_macros.h and are header-only, so the
# test compiles directly against the source tree (no SDK build/install or
# library link needed). It is built with AddressSanitizer + UBSan and
# -fno-sanitize-recover=all so any out-of-bounds write into the bitmask (which
# is heap-allocated at exactly sizeof(*) and therefore precisely bracketed by
# the ASan runtime) aborts. A clean exit 0 with all assertions passing is
# success.
#
# Usage: tools/phase0/tests/run_bitmask_oob_test.sh
set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${TEST_DIR}/../../.." && pwd)"
BIN="$(mktemp -d)/bitmask_oob_test"
trap 'rm -rf "$(dirname "${BIN}")"' EXIT

echo "[1/2] compiling bitmask_oob_test (ASan + UBSan)"
gcc -std=gnu11 -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
    -o "${BIN}" "${TEST_DIR}/bitmask_oob_test.c" \
    -I"${REPO_ROOT}/src/mmt_core/public_include" \
    -I"${REPO_ROOT}/src/mmt_tcpip/include" \
    -I"${REPO_ROOT}/src/mmt_tcpip/lib"

echo "[2/2] running bitmask_oob_test"
set +e
ASAN_OPTIONS=detect_leaks=0 "${BIN}"
rc=$?
set -e
if [ "${rc}" -ne 0 ]; then
    echo "✗ bitmask OOB test: FAIL (rc=${rc})"
    exit "${rc}"
fi

echo "✓ bitmask OOB test: PASS"
exit 0
