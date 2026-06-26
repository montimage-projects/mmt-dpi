#!/bin/bash
# Master test runner for all test suites
# Usage: ./run_all_tests.sh

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

# Run all test suites in order
run_test_suite "hashmap"
run_test_suite "memory"
run_test_suite "hexdump"
run_test_suite "mmt_utils"
run_test_suite "mmt_inet_ntop"
run_test_suite "avltree"
run_test_suite "citrix_ica_detection"
run_test_suite "http_header_case"

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
