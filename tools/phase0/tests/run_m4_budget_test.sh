#!/usr/bin/env bash
#
# run_m4_budget_test.sh — harness for tools/phase0/measure_m4_budget.sh, the
# one-command M4 budget measurement (issue #584).
#
# The real measurement needs the mmt-test bigFlows capture and minutes of
# replay, so this harness stands two vendored CI pcaps in for bigFlows and
# smallFlows and checks the script's contract, not the host's figures:
#   1. the evaluator's self-test (budget bounds, strict fetch-all bound,
#      missing rows, gate and harness outcomes, INCOMPLETE vs FAIL);
#   2. refusals before any build: no or an unknown --host-role, a bad
#      --iterations or --expect-sha256, a dataset whose sha256 differs, and
#      a dev-host run aimed at the committed audit reference
#      baseline/perf/throughput.txt — directly or through a symlinked
#      directory — which must leave that file byte-identical;
#   3. an end-to-end dev-host run (2 iterations, steps 4-5 skipped) against
#      one default-profile SDK: six 11-column rows, the host-identification
#      header (CPU model, kernel, dataset sha256 and size), the dev-host
#      record label, five "# m4:" checks plus a verdict that matches the exit
#      status and a re-run of --evaluate on the written file.
#
# Usage:
#   tools/phase0/tests/run_m4_budget_test.sh
#   MMT_SDK_PREBUILT=1 MMT_BUDGET_PREFIX=<prefix> ... — reuse an existing build
set -euo pipefail
export LC_ALL=C

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PHASE0_DIR="$(cd "${TEST_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${PHASE0_DIR}/../.." && pwd)"
SCRIPT="${PHASE0_DIR}/measure_m4_budget.sh"
REFERENCE="${PHASE0_DIR}/baseline/perf/throughput.txt"
PREFIX="${MMT_BUDGET_PREFIX:-$(mktemp -d "${TMPDIR:-/tmp}/m4budget.XXXXXX")}"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"; [ -n "${MMT_BUDGET_PREFIX:-}" ] || rm -rf "${PREFIX}"' EXIT

FAILS=0
fail() { echo "    ✗ $*"; FAILS=$((FAILS + 1)); }
ok()   { echo "    ✓ $*"; }

# Stand-ins for the mmt-test captures, under the names throughput_pcaps.txt lists.
DS="${WORK}/datasets"
mkdir -p "${DS}"
ln -s "${PHASE0_DIR}/ci/pcaps/ftp_multiple_session.pcap" "${DS}/bigFlows.pcap"
ln -s "${PHASE0_DIR}/ci/pcaps/dns_query.pcap" "${DS}/smallFlows.pcap"
BIG_SHA="$(sha256sum "${DS}/bigFlows.pcap" | cut -d' ' -f1)"
REF_SHA="$(sha256sum "${REFERENCE}" | cut -d' ' -f1)"

echo "[1/3] evaluator self-test"
if bash "${SCRIPT}" --self-test | sed 's/^/    /'; then ok "measure_m4_budget.sh --self-test"; else fail "measure_m4_budget.sh --self-test"; fi

echo "[2/3] refusals before any build"
# refused <label> <pattern> <args...>: the script must exit 2 with <pattern> on stderr.
refused() {
    local label="$1" pattern="$2" rc
    shift 2
    set +e
    ( cd "${WORK}" && MMT_PREFIX="${WORK}/no-prefix" MMT_SDK_PREBUILT=1 bash "${SCRIPT}" "$@" ) >"${WORK}/out" 2>"${WORK}/err"
    rc=$?
    set -e
    if [ "${rc}" -ne 2 ]; then fail "${label}: exit ${rc}, expected 2 ($(tail -n 1 "${WORK}/err"))"
    elif ! grep -q -- "${pattern}" "${WORK}/err"; then fail "${label}: stderr lacks '${pattern}': $(cat "${WORK}/err")"
    else ok "${label}: $(head -n 1 "${WORK}/err")"
    fi
}
refused "no --host-role"            "is required" --datasets "${DS}"
refused "an unknown --host-role"    "takes audit or dev" --host-role prod --datasets "${DS}"
refused "--iterations 0"            "positive integer" --host-role dev --iterations 0 --datasets "${DS}"
refused "a malformed --expect-sha256" "64 lowercase hex" --host-role dev --expect-sha256 abc --datasets "${DS}"
refused "another dataset's sha256"  "another dataset" --host-role dev --datasets "${DS}" \
        --out "${WORK}/x.txt" --expect-sha256 "$(printf '%064d' 0)"
refused "a dev run aimed at the audit reference" "refuses to write" --host-role dev --datasets "${DS}" \
        --out "${REFERENCE}"
ln -s "$(dirname "${REFERENCE}")" "${WORK}/perf-link"
refused "a dev run aimed at the reference through a symlink" "refuses to write" --host-role dev \
        --datasets "${DS}" --out "${WORK}/perf-link/throughput.txt"
if [ "$(sha256sum "${REFERENCE}" | cut -d' ' -f1)" = "${REF_SHA}" ]; then
    ok "the committed reference is unchanged"
else
    fail "the committed reference changed"
fi

echo "[3/3] end-to-end dev-host run"
if [ "${MMT_SDK_PREBUILT:-0}" = "1" ]; then
    echo "    reusing prebuilt SDK at ${PREFIX} (MMT_SDK_PREBUILT=1)"
    [ -f "${PREFIX}/dpi/include/mmt_core.h" ] || { echo "✗ no installed SDK under ${PREFIX}" >&2; exit 2; }
else
    echo "    building + installing the default SDK -> ${PREFIX}"
    make -C "${REPO_ROOT}/sdk" clean >/dev/null 2>&1
    if ! make -C "${REPO_ROOT}/sdk" MMT_BASE="${PREFIX}" -j"$(nproc)" >"${WORK}/build.log" 2>&1 \
       || ! make -C "${REPO_ROOT}/sdk" MMT_BASE="${PREFIX}" install >>"${WORK}/build.log" 2>&1; then
        echo "✗ SDK build/install failed — last lines:" >&2; tail -20 "${WORK}/build.log" >&2; exit 1
    fi
fi
OUT="${WORK}/m4.txt"
set +e
( cd "${WORK}" && MMT_PREFIX="${PREFIX}" MMT_SDK_PREBUILT=1 bash "${SCRIPT}" --host-role dev --iterations 2 \
      --datasets "${DS}" --out "${OUT}" --skip-instructions --skip-harness ) >"${WORK}/run.log" 2>&1
rc=$?
set -e
if [ "${rc}" -ne 1 ] && [ "${rc}" -ne 3 ]; then
    fail "the dev run exited ${rc}, expected 1 or 3 (steps skipped): $(tail -n 3 "${WORK}/run.log" | tr '\n' ' ')"
elif [ ! -f "${OUT}" ]; then
    fail "the dev run wrote no ${OUT}"
else
    ok "the dev run exited ${rc} and wrote its record"
    rows="$(grep -vc '^#' "${OUT}" || true)"
    bad="$(awk -F'\t' '!/^#/ && NF != 11' "${OUT}" | wc -l)"
    if [ "${rows}" -eq 6 ] && [ "${bad}" -eq 0 ]; then
        ok "6 rows of 11 columns (2 pcaps x bare attrs8 all)"
    else
        fail "${rows} rows, ${bad} not of 11 columns"
    fi
    for mode in bare attrs8 all; do
        grep -q "^bigFlows.pcap	${mode}	" "${OUT}" || fail "no bigFlows.pcap ${mode} row"
    done
    want_hdr=("# host: $(uname -m) | cpu: $(nproc)"
              "# cpu_model: "
              "| kernel: $(uname -r) |"
              "| iterations: 2"
              "# dataset: bigFlows.pcap | sha256: ${BIG_SHA} | bytes: $(stat -L -c %s "${DS}/bigFlows.pcap")"
              "# dataset: smallFlows.pcap | sha256: "
              "# record: DEV HOST, NOT the audit host"
              "# m4 budget (issue #584): DEV HOST, NOT the audit host"
              "# m4: instruction gate (check_instructions.sh): SKIPPED"
              "# m4: run_throughput_attrs_test.sh: SKIPPED")
    for want in "${want_hdr[@]}"; do
        grep -qF -- "${want}" "${OUT}" || fail "the record lacks '${want}'"
    done
    if grep -q '^# cpu_model: unknown' "${OUT}"; then fail "the CPU model was not identified"; fi
    if [ "$(grep -c '^# m4: ' "${OUT}")" -eq 6 ]; then
        ok "five checks and a verdict"
    else
        fail "expected 6 '# m4:' lines, got $(grep -c '^# m4: ' "${OUT}")"
    fi
    case "${rc}" in
        1) grep -q '^# m4: verdict: FAIL' "${OUT}" || fail "exit 1 without a FAIL verdict" ;;
        3) grep -q '^# m4: verdict: INCOMPLETE (2 of 5' "${OUT}" || fail "exit 3 without an INCOMPLETE verdict" ;;
    esac
    # --evaluate on the written file reproduces the recorded checks and status.
    grep -v '^# m4' "${OUT}" > "${WORK}/rows.txt"
    set +e
    bash "${SCRIPT}" --evaluate "${WORK}/rows.txt" --gate skipped --harness skipped >"${WORK}/eval.txt" 2>&1
    erc=$?
    set -e
    if [ "${erc}" -eq "${rc}" ] && diff -q <(grep '^# m4: ' "${OUT}") "${WORK}/eval.txt" >/dev/null; then
        ok "--evaluate reproduces the record (exit ${erc})"
    else
        fail "--evaluate exit ${erc} vs ${rc}, or its lines differ: $(diff <(grep '^# m4: ' "${OUT}") "${WORK}/eval.txt" | head -n 4 | tr '\n' ' ')"
    fi
    if [ "${FAILS}" -eq 0 ]; then grep '^# m4: ' "${OUT}" | sed 's/^/      /'; fi
fi
[ "$(sha256sum "${REFERENCE}" | cut -d' ' -f1)" = "${REF_SHA}" ] || fail "the end-to-end run changed the committed reference"

if [ "${FAILS}" -eq 0 ]; then
    echo "✓ M4 budget measurement (issue #584) test: PASS"
    exit 0
fi
echo "✗ M4 budget measurement (issue #584) test: FAIL (${FAILS} check(s))"
exit 1
