#!/bin/bash
# Run hashmap tests
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Source paths
CORE_SRC="$PROJECT_DIR/src/mmt_core/src"
CORE_PRIVATE_INC="$PROJECT_DIR/src/mmt_core/private_include"
CORE_PUBLIC_INC="$PROJECT_DIR/src/mmt_core/public_include"

# Compile test
echo "Compiling hashmap tests..."
${CC:-gcc} ${EXTRA_CFLAGS:-} -Wall -Wextra -std=c11 \
    -D'u_char=unsigned char' \
    -I"$CORE_PRIVATE_INC" \
    -I"$CORE_PUBLIC_INC" \
    -I"$PROJECT_DIR/src/mmt_tcpip/lib" \
    -o "$SCRIPT_DIR/test_hashmap" \
    "$SCRIPT_DIR/test_hashmap.c" \
    "$CORE_SRC/hashmap.c" \
    "$CORE_SRC/memory.c"

# Run tests
echo "Running hashmap tests..."
if "$SCRIPT_DIR/test_hashmap"; then
    echo "Hashmap tests: PASSED"
else
    echo "Hashmap tests: FAILED"
    exit 1
fi
