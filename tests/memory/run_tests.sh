#!/bin/bash
# Run memory allocator tests
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Source paths
CORE_SRC="$PROJECT_DIR/src/mmt_core/src"
CORE_PRIVATE_INC="$PROJECT_DIR/src/mmt_core/private_include"
CORE_PUBLIC_INC="$PROJECT_DIR/src/mmt_core/public_include"

# Compile test
echo "Compiling memory tests..."
${CC:-gcc} ${EXTRA_CFLAGS:-} -Wall -Wextra -std=c11 \
    -D'u_char=unsigned char' \
    -I"$CORE_PUBLIC_INC" \
    -I"$CORE_PRIVATE_INC" \
    -o "$SCRIPT_DIR/test_memory" \
    "$SCRIPT_DIR/test_memory.c" \
    "$CORE_SRC/memory.c"

# Run tests
echo "Running memory tests..."
"$SCRIPT_DIR/test_memory"
EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    echo "Memory tests: PASSED"
else
    echo "Memory tests: FAILED"
fi

exit $EXIT_CODE
