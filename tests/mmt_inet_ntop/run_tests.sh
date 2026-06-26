#!/bin/bash
# Run mmt_inet_ntop tests
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Source paths
CORE_SRC="$PROJECT_DIR/src/mmt_core/src"
CORE_PUBLIC_INC="$PROJECT_DIR/src/mmt_core/public_include"

# Compile test
echo "Compiling mmt_inet_ntop tests..."
${CC:-gcc} ${EXTRA_CFLAGS:-} -Wall -Wextra -std=c11 \
    -D'u_char=unsigned char' \
    -I"$CORE_PUBLIC_INC" \
    -o "$SCRIPT_DIR/test_mmt_inet_ntop" \
    "$SCRIPT_DIR/test_mmt_inet_ntop.c" \
    "$CORE_SRC/mmt_inet_ntop.c"

# Run tests
echo "Running mmt_inet_ntop tests..."
"$SCRIPT_DIR/test_mmt_inet_ntop"
EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    echo "mmt_inet_ntop tests: PASSED"
else
    echo "mmt_inet_ntop tests: FAILED"
fi

exit $EXIT_CODE
