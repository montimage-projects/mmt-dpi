#!/bin/bash
# Run hexdump tests
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Source paths
CORE_SRC="$PROJECT_DIR/src/mmt_core/src"
CORE_PRIVATE_INC="$PROJECT_DIR/src/mmt_core/private_include"

# Compile test
echo "Compiling hexdump tests..."
${CC:-gcc} ${EXTRA_CFLAGS:-} -Wall -Wextra -std=c11 \
    -I"$CORE_PRIVATE_INC" \
    -o "$SCRIPT_DIR/test_hexdump" \
    "$SCRIPT_DIR/test_hexdump.c" \
    "$CORE_SRC/hexdump.c"

# Run tests
echo "Running hexdump tests..."
if "$SCRIPT_DIR/test_hexdump"; then
    echo "Hexdump tests: PASSED"
else
    echo "Hexdump tests: FAILED"
    exit 1
fi
