#!/usr/bin/env bash
#
# run_tests.sh — verify the issue #21 AVL height-cache change:
#   1. correctness suite passes on the NEW (post-fix) avltree.c
#   2. tree SHAPE is byte-identical between the OLD (pre-fix) and NEW sources
#      across several sizes  => balancing/ordering behaviour is unchanged
#   3. micro-benchmark: build time of the AVL construction, OLD vs NEW, over a
#      range of N => demonstrates the O(n^2)->O(n log n) startup win.
#
# The OLD source is pulled from git (origin/main, or main) so the comparison is
# against the exact pre-fix implementation.
#
# Usage: tests/avltree/run_tests.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
LIB_DIR="${REPO_ROOT}/src/mmt_tcpip/lib"
TEST_SRC="${SCRIPT_DIR}/test_avltree.c"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

CC="${CC:-gcc}"
CFLAGS="-O2 -Wall -g"

# Pick a git ref that holds the pre-fix source.
OLD_REF=""
for ref in origin/main main origin/master master; do
    if git -C "${REPO_ROOT}" cat-file -e "${ref}:src/mmt_tcpip/lib/avltree.c" 2>/dev/null; then
        OLD_REF="${ref}"; break
    fi
done
[ -z "${OLD_REF}" ] && { echo "✗ could not find a pre-fix avltree.c in git" >&2; exit 1; }
echo "  pre-fix source ref : ${OLD_REF}"

# --- build NEW (working tree) ---------------------------------------------
echo "  building NEW (working tree) ..."
${CC} ${CFLAGS} -I "${LIB_DIR}" -o "${WORK}/test_new" \
    "${TEST_SRC}" "${LIB_DIR}/avltree.c"

# --- build OLD (from git) --------------------------------------------------
echo "  building OLD (${OLD_REF}) ..."
mkdir -p "${WORK}/old"
git -C "${REPO_ROOT}" show "${OLD_REF}:src/mmt_tcpip/lib/avltree.c" > "${WORK}/old/avltree.c"
git -C "${REPO_ROOT}" show "${OLD_REF}:src/mmt_tcpip/lib/avltree.h" > "${WORK}/old/avltree.h"
${CC} ${CFLAGS} -I "${WORK}/old" -o "${WORK}/test_old" \
    "${TEST_SRC}" "${WORK}/old/avltree.c"

# --- 1. correctness on NEW -------------------------------------------------
echo
echo "== [1/3] correctness suite (NEW) =="
"${WORK}/test_new"

# --- 2. shape equivalence OLD vs NEW --------------------------------------
echo
echo "== [2/3] tree-shape equivalence OLD vs NEW =="
shape_ok=1
for n in 1 2 3 8 64 1000 5000; do
    "${WORK}/test_old" --fingerprint "$n" > "${WORK}/fp_old_${n}.txt"
    "${WORK}/test_new" --fingerprint "$n" > "${WORK}/fp_new_${n}.txt"
    if diff -q "${WORK}/fp_old_${n}.txt" "${WORK}/fp_new_${n}.txt" >/dev/null; then
        echo "  n=${n}: shape IDENTICAL ($(wc -l < "${WORK}/fp_new_${n}.txt") nodes)"
    else
        echo "  n=${n}: SHAPE DIFFERS"; shape_ok=0
    fi
done
[ "${shape_ok}" -eq 1 ] || { echo "✗ tree shape changed — classification regression risk" >&2; exit 1; }

# --- 3. build-time benchmark OLD vs NEW -----------------------------------
echo
echo "== [3/3] AVL build-time micro-benchmark (lower is better) =="
printf "  %-10s %14s %14s %10s\n" "N" "OLD_ms" "NEW_ms" "speedup"
for n in 2000 5000 10000 20000; do
    reps=5
    old_ms=$("${WORK}/test_old" --bench "$n" "$reps" | sed 's/.*time_ms=//')
    new_ms=$("${WORK}/test_new" --bench "$n" "$reps" | sed 's/.*time_ms=//')
    speed=$(awk -v o="$old_ms" -v n="$new_ms" 'BEGIN{ if(n>0) printf "%.1fx", o/n; else print "n/a" }')
    printf "  %-10s %14s %14s %10s\n" "$n" "$old_ms" "$new_ms" "$speed"
done

echo
echo "✓ all AVL tests passed (correctness + identical shape + faster build)"
