#!/bin/bash
# Master test runner for all test suites
# Usage: ./run_all_tests.sh [suite ...]
#   With no arguments, runs every suite below. Pass one or more suite names
#   (directory names under tests/) to run only those — e.g. CI runs just the
#   core suites under EXTRA_CFLAGS=-fsigned-char.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PASS=0
FAIL=0
TOTAL=0

echo "============================================"
echo "  MMT-DPI Test Suite Runner"
echo "============================================"
echo ""

run_test_suite() {
    local suite_name=$1
    local test_dir="$SCRIPT_DIR/$suite_name"
    local test_script="$test_dir/run_tests.sh"

    TOTAL=$((TOTAL + 1))

    if [ ! -f "$test_script" ]; then
        echo "  [SKIP] $suite_name: run_tests.sh not found"
        return
    fi

    echo "--- Running: $suite_name ---"
    if bash "$test_script" 2>&1; then
        echo "  ✓ $suite_name: PASSED"
        PASS=$((PASS + 1))
    else
        echo "  ✗ $suite_name: FAILED"
        FAIL=$((FAIL + 1))
    fi
    echo ""
}

# Default suite list (run in this order when no arguments are given).
DEFAULT_SUITES=(
    hashmap
    memory
    hexdump
    mmt_utils
    mmt_inet_ntop
    avltree
    citrix_ica_detection
    http_header_case
)

# Run the requested suites, or all of them if none were named on the CLI.
if [ "$#" -gt 0 ]; then
    SUITES=("$@")
else
    SUITES=("${DEFAULT_SUITES[@]}")
fi

for suite in "${SUITES[@]}"; do
    run_test_suite "$suite"
done

echo "============================================"
echo "  Test Results"
echo "============================================"
echo "  Total:  $TOTAL"
echo "  Passed: $PASS"
echo "  Failed: $FAIL"
echo "============================================"

if [ $FAIL -gt 0 ]; then
    exit 1
fi
exit 0
