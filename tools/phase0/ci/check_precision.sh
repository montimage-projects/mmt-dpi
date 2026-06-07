#!/usr/bin/env bash
#
# check_precision.sh — CI gate for the Phase 7 (M9, issue #74) precision/recall
# baseline.
#
# Runs the labelled-pcap precision/recall harness (tools/phase0/phase0_precision.c)
# over the labelled CI golden subset (tools/phase0/ci/labels.txt) against a
# freshly built+installed library, and diffs the resulting metrics against the
# committed baseline (tools/phase0/ci/baseline/precision.txt). A non-empty diff
# means a change moved classification accuracy on the labelled set — the gate
# fails so the change is reviewed (acceptance criterion: precision/recall
# "improves or holds"). If the change is an intentional improvement, refresh the
# baseline in the same PR.
#
# Used by .github/workflows/phase0-baseline.yml. Runnable locally too:
#   tools/phase0/ci/check_precision.sh
#
# On mismatch it writes the freshly captured metrics to
#   tools/phase0/ci/baseline/precision.actual.txt
# which CI uploads as an artifact, so refreshing the baseline is a copy away.
#
set -euo pipefail

CI_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PHASE0_DIR="$(cd "${CI_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${PHASE0_DIR}/../.." && pwd)"
LABELS="${CI_DIR}/labels.txt"
PCAPS_DIR="${CI_DIR}/pcaps"
EXPECTED="${CI_DIR}/baseline/precision.txt"
ACTUAL="${CI_DIR}/baseline/precision.actual.txt"
PREFIX="${MMT_PREFIX:-/tmp/mmt-phase0}"
BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "${BUILD_DIR}"' EXIT

if [ ! -f "${LABELS}" ]; then
    echo "✗ labelled-pcap manifest missing: ${LABELS}" >&2
    exit 1
fi

# --- build + install the library -------------------------------------------
echo "[1/3] building + installing library -> ${PREFIX}"
make -C "${REPO_ROOT}/sdk" -j"$(nproc 2>/dev/null || echo 4)" MMT_BASE="${PREFIX}" \
    >"${BUILD_DIR}/build.log" 2>&1 || {
        echo "✗ library build failed — last lines:" >&2
        tail -20 "${BUILD_DIR}/build.log" >&2
        exit 1
    }
make -C "${REPO_ROOT}/sdk" MMT_BASE="${PREFIX}" install >>"${BUILD_DIR}/build.log" 2>&1

INC="${PREFIX}/dpi/include"
LIB="${PREFIX}/dpi/lib"
export LD_LIBRARY_PATH="${LIB}:${LD_LIBRARY_PATH:-}"

echo "[2/3] compiling phase0_precision"
gcc -O2 -Wall -o "${BUILD_DIR}/phase0_precision" \
    "${PHASE0_DIR}/phase0_precision.c" -I "${INC}" -L "${LIB}" -lmmt_core -ldl -lpcap

echo "[3/3] running the precision/recall harness over the labelled set"
RAW="${BUILD_DIR}/raw.tsv"
: > "${RAW}"
# Run the harness from a neutral dir so the SDK's CWD-relative "plugins/" lookup
# misses and falls back to ${PREFIX}/plugins (matches capture_baseline.sh).
while IFS= read -r line; do
    # strip comments / blanks
    line="${line%%#*}"
    rel="$(printf '%s' "${line}" | awk '{print $1}')"
    label="$(printf '%s' "${line}" | awk '{print $2}')"
    [ -z "${rel}" ] && continue
    pcap="${PCAPS_DIR}/${rel}"
    if [ ! -f "${pcap}" ]; then
        echo "  ⚠ missing pcap: ${rel}" >&2
        continue
    fi
    # output: <label> <total> <tp> <fp> <app_unknown>. Don't let a harness
    # non-zero exit (e.g. an unsupported link-type) abort the whole gate under
    # 'set -e'; flag the pcap and skip it instead.
    out="$(cd "${BUILD_DIR}" && "${BUILD_DIR}/phase0_precision" "${pcap}" "${label}" 2>/dev/null)" || out=""
    if [ -z "${out}" ]; then
        echo "  ⚠ harness produced no output for: ${rel}" >&2
        continue
    fi
    printf '%s\t%s\n' "${rel}" "${out}" >> "${RAW}"
done < "${LABELS}"

# --- render the deterministic metrics file ---------------------------------
# Per-pcap rows + per-protocol and overall micro-averages. recall/precision are
# computed from integer counts so the formatted output is reproducible.
render() {
    awk -F'\t' '
    function ratio(n, d) { return (d == 0) ? "n/a" : sprintf("%.4f", n / d) }
    {
        # cols: rel label total tp fp app_unknown
        rel=$1; label=$2; total=$3; tp=$4; fp=$5; unk=$6;
        printf "%-28s %-8s total=%-6d tp=%-6d fp=%-6d unknown=%-6d recall=%s precision=%s\n",
               rel, label, total, tp, fp, unk, ratio(tp, total), ratio(tp, tp + fp);
        p_total[label]+=total; p_tp[label]+=tp; p_fp[label]+=fp; p_unk[label]+=unk;
        o_total+=total; o_tp+=tp; o_fp+=fp; o_unk+=unk;
        if (!(label in seen)) { order[++no]=label; seen[label]=1 }
    }
    END {
        print "";
        print "# --- per-protocol (micro-averaged) ---";
        for (i = 1; i <= no; i++) {
            l = order[i];
            printf "proto   %-8s total=%-6d tp=%-6d fp=%-6d unknown=%-6d recall=%s precision=%s\n",
                   l, p_total[l], p_tp[l], p_fp[l], p_unk[l],
                   ratio(p_tp[l], p_total[l]), ratio(p_tp[l], p_tp[l] + p_fp[l]);
        }
        print "";
        print "# --- overall (micro-averaged) ---";
        printf "overall          total=%-6d tp=%-6d fp=%-6d unknown=%-6d recall=%s precision=%s\n",
               o_total, o_tp, o_fp, o_unk, ratio(o_tp, o_total), ratio(o_tp, o_tp + o_fp);
    }' "${RAW}"
}

{
    echo "# Phase 7 (M9, issue #74) precision/recall baseline — labelled CI golden subset."
    echo "# Deterministic: derived from the classifier's decisions (see phase0_precision.c)."
    echo "# Refresh with: tools/phase0/ci/check_precision.sh (then commit precision.txt)."
    echo "#"
    render
} > "${BUILD_DIR}/precision.txt"

if [ ! -f "${EXPECTED}" ]; then
    cp "${BUILD_DIR}/precision.txt" "${EXPECTED}"
    echo
    echo "○ No committed precision baseline found — wrote one to:"
    echo "    ${EXPECTED#"${REPO_ROOT}/"}"
    echo "  Review it and commit it."
    cat "${EXPECTED}"
    exit 0
fi

if diff -u "${EXPECTED}" "${BUILD_DIR}/precision.txt"; then
    echo
    echo "✓ Phase 7 precision/recall gate: PASS (metrics match the baseline)"
    exit 0
else
    cp "${BUILD_DIR}/precision.txt" "${ACTUAL}"
    echo
    echo "✗ Phase 7 precision/recall gate: FAIL"
    echo "  Classification accuracy on the labelled set changed (diff above)."
    echo "  If this is an INTENTIONAL improvement, refresh the baseline:"
    echo "    cp ${ACTUAL#"${REPO_ROOT}/"} ${EXPECTED#"${REPO_ROOT}/"}"
    echo "  and commit it in the same PR, explaining the change."
    exit 1
fi
