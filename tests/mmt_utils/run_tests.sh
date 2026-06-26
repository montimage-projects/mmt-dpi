#!/bin/bash
# Run mmt_utils tests
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Source paths
CORE_SRC="$PROJECT_DIR/src/mmt_core/src"
CORE_PUBLIC_INC="$PROJECT_DIR/src/mmt_core/public_include"

# Compile test
echo "Compiling mmt_utils tests..."
${CC:-gcc} ${EXTRA_CFLAGS:-} -Wall -Wextra -std=c11 \
    -D'u_char=unsigned char' \
    -I"$CORE_PUBLIC_INC" \
    -o "$SCRIPT_DIR/test_mmt_utils" \
    "$SCRIPT_DIR/test_mmt_utils.c" \
    "$CORE_SRC/mmt_utils.c" \
    -lm

# Run tests
echo "Running mmt_utils tests..."
if "$SCRIPT_DIR/test_mmt_utils"; then
    echo "mmt_utils tests: PASSED"
else
    echo "mmt_utils tests: FAILED"
    exit 1
fi
