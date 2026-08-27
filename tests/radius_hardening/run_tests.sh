#!/usr/bin/env bash
# run_tests.sh — regression for issue #128: RADIUS parser hardening.
#
# Verifies crafted-packet guards in src/mmt_tcpip/lib/protocols/proto_radius.c:
#   - len==1 TLV rejected (F-BUG-102)
#   - large vlen 67-255 clamped to BINARY_64DATA_LEN (no overflow)
#   - truncated type-26 vendor-specific TLV guards
#   - 3-5-byte TLVs rejected for read_be32 sites
#
# Two layers:
#   1. source-level grep: ensure the fixed guards exist in proto_radius.c
#   2. runtime harness: synthetic packets exercise the parsing/extraction
#      logic under ASan+UBSan (via EXTRA_CFLAGS from run_all_tests.sh)
#
# Usage: tests/radius_hardening/run_tests.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SRC="${REPO_ROOT}/src/mmt_tcpip/lib/protocols/proto_radius.c"
TEST_SRC="${SCRIPT_DIR}/test_radius_hardening.c"
TEST_BIN="${SCRIPT_DIR}/test_radius_hardening"

echo "  repo root : ${REPO_ROOT}"
echo "  source    : ${SRC#"$REPO_ROOT"/}"

# --- 1. source-level guard verification ---------------------------------
echo "  [1/2] verifying source guards in proto_radius.c ..."
fail=0
check_grep() {
    local desc="$1" pat="$2"
    if grep -q -E -- "$pat" "$SRC"; then
        echo "    ok   $desc"
    else
        echo "    FAIL $desc (pattern: $pat)" >&2
        fail=1
    fi
}
check_grep "TLV len<2 rejection (F-BUG-102)" 'current_tlv->len < 2'
check_grep "TLV truncated guard (caplen check)" 'tlv_offset \+ \(size_t\)current_tlv->len'
check_grep "binary vlen clamp to BINARY_64DATA_LEN" 'vlen > BINARY_64DATA_LEN'
check_grep "string vlen clamp (BINARY_64DATA_LEN -1)" 'BINARY_64DATA_LEN - 1'
check_grep "read_be32 len<6 guard (NAS-IP etc)" '->len < 6'
check_grep "vendor specific v_remaining <6 guard" 'v_remaining < 6'
check_grep "vendor sub-TLV len<2 guard" 'tlv->len < 2'
check_grep "vendor sub_remaining len guard" 'tlv->len > sub_remaining'
check_grep "vendor type bounds check" 'VENDOR_3GPP_MAX_TLV_TYPE'

if [ "$fail" -ne 0 ]; then
    echo "✗ source guard verification failed" >&2
    exit 1
fi

# --- 2. compile + run harness -------------------------------------------
echo "  [2/2] compiling and running harness ..."
read -r -a extra_cflags <<< "${EXTRA_CFLAGS:-}"
# shellcheck disable=SC2153
${CC:-gcc} "${extra_cflags[@]}" -O2 -Wall -Wextra -std=c11 \
    -o "${TEST_BIN}" "${TEST_SRC}"

echo "  running test_radius_hardening ..."
if "${TEST_BIN}"; then
    echo
    echo "✓ RADIUS hardening regression tests passed"
else
    echo "✗ RADIUS hardening regression tests failed" >&2
    exit 1
fi
