#!/usr/bin/env bash
#
# measure_m4_budget.sh — one command that measures the M4 performance budget
# (issue #584, plan task 19.5) and writes it in the format of
# tools/phase0/baseline/perf/throughput.txt.
#
# The budget, the audit host's reference figures (issues #555/#584):
#   bigFlows bare      pps              >= 3,106,798
#   bigFlows bare      library_rss_kib  <= 21,428 (the peak over --iterations)
#   bigFlows fetch-all ns_per_pkt       <  1,704   (target <= 1,000)
#   the CI instruction-count gate (tools/phase0/ci/check_instructions.sh) green
#
# Steps, all against ONE default-profile (-O3, release) SDK build:
#   1. identify the host and the dataset (CPU model, cores, kernel, GCC, OS,
#      commit, sha256 of every throughput_pcaps.txt capture);
#   2. build + install the SDK into an isolated prefix (make -C sdk clean
#      first, so an in-tree build is discarded);
#   3. tools/phase0/capture_perf.sh: bigFlows and smallFlows in the bare,
#      attrs8 and all modes — the rows throughput.txt holds;
#   4. tools/phase0/ci/check_instructions.sh: Ir/pkt per mode over the
#      vendored CI pcaps, compared with ci/baseline/instructions.txt;
#   5. tools/phase0/tests/run_throughput_attrs_test.sh: the #555 harness;
# then appends one "# m4:" comment line per check and a verdict to the rows.
# The output is written only once every step has run, so a failed run never
# leaves a partial file behind.
#
# Usage:
#   tools/phase0/measure_m4_budget.sh --host-role audit|dev [--iterations N]
#       [--out FILE] [--datasets DIR] [--taskset CPULIST]
#       [--expect-sha256 HEX] [--skip-instructions] [--skip-harness]
#   tools/phase0/measure_m4_budget.sh --evaluate FILE [--instructions FILE]
#       [--gate pass|fail|error|skipped] [--harness pass|fail|skipped]
#   tools/phase0/measure_m4_budget.sh --self-test
#
#   --host-role ROLE   required. `audit`: the audit host; writes the committed
#                      reference tools/phase0/baseline/perf/throughput.txt by
#                      default. `dev`: any other host; writes
#                      baseline/perf/throughput.dev-host.txt by default and
#                      refuses to write the committed reference.
#   --iterations N     replay passes per (pcap, mode) (default 200, the
#                      committed reference's count); library_rss_kib is the
#                      peak over them, so it rises with N
#   --out FILE         output file (default per role, above)
#   --datasets DIR     mmt-test data-sets root (default $MMT_TEST_DATASETS,
#                      else <repo>/../mmt-test/data-sets)
#   --taskset CPULIST  pin the replay with `taskset -c CPULIST` (on a
#                      big.LITTLE host, name the big cores)
#   --expect-sha256 H  refuse to run unless bigFlows.pcap has this sha256
#   --skip-instructions, --skip-harness
#                      skip step 4 or 5; the verdict is then INCOMPLETE
#   --evaluate FILE    only evaluate an existing throughput file (no build)
#   --self-test        the evaluator on fixtures
# Environment:
#   MMT_PREFIX          install prefix (default: a private mktemp dir, removed)
#   MMT_SDK_PREBUILT=1  reuse the SDK already installed under MMT_PREFIX
#
# Exit: 0 budget met, 1 a check failed, 3 incomplete (a step skipped, nothing
# failed), 2 bad usage, missing input or a step that could not run.
set -euo pipefail
export LC_ALL=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
REFERENCE="${SCRIPT_DIR}/baseline/perf/throughput.txt"
DEV_DEFAULT="${SCRIPT_DIR}/baseline/perf/throughput.dev-host.txt"
INSTR_ACTUAL="${SCRIPT_DIR}/ci/baseline/instructions.actual.txt"
LIST="${SCRIPT_DIR}/throughput_pcaps.txt"

# The M4 budget (issue #584's acceptance criteria).
M4_PPS_MIN=3106798
M4_RSS_MAX_KIB=21428
M4_ALL_NS_MAX=1704      # strictly below
M4_ALL_NS_TARGET=1000   # at or below: the target, reported, not gated
M4_PCAP=bigFlows.pcap

usage() { sed -n '2,/^set -euo/p' "$0" | sed -e '$d' -e 's/^# \{0,1\}//'; }

# evaluate THROUGHPUT INSTRUCTIONS GATE HARNESS — one "# m4:" line per check
# and the verdict on stdout; returns 0 PASS, 1 FAIL, 3 INCOMPLETE.
#   THROUGHPUT    a file in throughput.txt's format
#   INSTRUCTIONS  a check_instructions.sh measurement (or "" when none)
#   GATE          check_instructions.sh outcome: pass | fail | error | skipped
#   HARNESS       run_throughput_attrs_test.sh outcome: pass | fail | skipped
evaluate() {
    local file="$1" instr="$2" gate="$3" harness="$4" irs=""
    [ -f "${file}" ] || { echo "✗ no throughput file: ${file}" >&2; return 2; }
    if [ -n "${instr}" ] && [ -f "${instr}" ]; then
        irs="$(awk -F'\t' '$1 == "total" { out = out (n++ ? ", " : "") $2 " " $5 } END { print out }' "${instr}")"
    fi
    awk -F'\t' -v pcap="${M4_PCAP}" -v pps_min="${M4_PPS_MIN}" -v rss_max="${M4_RSS_MAX_KIB}" \
        -v ns_max="${M4_ALL_NS_MAX}" -v ns_target="${M4_ALL_NS_TARGET}" \
        -v gate="${gate}" -v harness="${harness}" -v irs="${irs}" '
        function num(v) { return v ~ /^-?[0-9]+(\.[0-9]+)?$/ }
        $1 == pcap && NF >= 11 { pps[$2] = $7; rss[$2] = $9; ns[$2] = $11; it[$2] = $5; seen[$2] = 1 }
        END {
            fails = 0; skips = 0
            if (!("bare" in seen) || !num(pps["bare"])) {
                printf "# m4: %s bare pps: FAIL (no bare row)\n", pcap; fails++
            } else {
                ok = (pps["bare"] + 0 >= pps_min)
                printf "# m4: %s bare pps %s >= %s: %s\n", pcap, pps["bare"], pps_min, ok ? "PASS" : "FAIL"
                fails += !ok
            }
            if (!("bare" in seen) || !num(rss["bare"]) || rss["bare"] + 0 < 0) {
                printf "# m4: %s bare library_rss_kib: FAIL (no bare row, or RSS unavailable)\n", pcap; fails++
            } else {
                ok = (rss["bare"] + 0 <= rss_max)
                printf "# m4: %s bare library_rss_kib %s <= %s (peak over %s iterations): %s\n", \
                    pcap, rss["bare"], rss_max, it["bare"], ok ? "PASS" : "FAIL"
                fails += !ok
            }
            if (!("all" in seen) || !num(ns["all"])) {
                printf "# m4: %s fetch-all ns_per_pkt: FAIL (no all row)\n", pcap; fails++
            } else {
                ok = (ns["all"] + 0 < ns_max)
                printf "# m4: %s fetch-all ns_per_pkt %s < %s: %s (target <= %s: %s)\n", pcap, ns["all"], \
                    ns_max, ok ? "PASS" : "FAIL", ns_target, (ns["all"] + 0 <= ns_target) ? "met" : "missed"
                fails += !ok
            }
            ir = (irs != "") ? " - Ir/pkt " irs : ""
            if (gate == "pass")         printf "# m4: instruction gate (check_instructions.sh): PASS%s\n", ir
            else if (gate == "skipped") { printf "# m4: instruction gate (check_instructions.sh): SKIPPED\n"; skips++ }
            else if (gate == "fail")    { printf "# m4: instruction gate (check_instructions.sh): FAIL%s\n", ir; fails++ }
            else                        { printf "# m4: instruction gate (check_instructions.sh): FAIL (could not run)\n"; fails++ }
            if (harness == "pass")         printf "# m4: run_throughput_attrs_test.sh: PASS\n"
            else if (harness == "skipped") { printf "# m4: run_throughput_attrs_test.sh: SKIPPED\n"; skips++ }
            else                           { printf "# m4: run_throughput_attrs_test.sh: FAIL\n"; fails++ }
            if (fails)      { printf "# m4: verdict: FAIL (%d of 5 checks failed)\n", fails; exit 1 }
            else if (skips) { printf "# m4: verdict: INCOMPLETE (%d of 5 checks skipped)\n", skips; exit 3 }
            printf "# m4: verdict: PASS\n"
        }' "${file}"
}

self_test() {
    local dir fails=0
    dir="$(mktemp -d)"
    # fixture <bare pps> <bare library_rss_kib> <all ns_per_pkt> — "" drops the row
    fixture() {
        {
            printf '# pcap\tmode\tattrs\tpackets\titerations\telapsed_s\tpps\tharness_rss_kib\tlibrary_rss_kib\tpeak_rss_kib\tns_per_pkt\n'
            [ -z "$1" ] || printf 'bigFlows.pcap\tbare\t0\t791615\t20\t5.0\t%s\t403976\t%s\t440264\t%s\n' "$1" "$2" \
                "$(awk -v p="$1" 'BEGIN { printf "%.1f", 1e9 / p }')"
            printf 'bigFlows.pcap\tattrs8\t8\t791615\t20\t5.0\t3000000\t403976\t20000\t440136\t333.3\n'
            [ -z "$3" ] || printf 'bigFlows.pcap\tall\t7450\t791615\t20\t5.0\t%s\t403976\t20000\t441200\t%s\n' \
                "$(awk -v n="$3" 'BEGIN { printf "%.0f", 1e9 / n }')" "$3"
            printf 'smallFlows.pcap\tbare\t0\t14261\t20\t0.1\t1\t10076\t99999999\t19500\t1e9\n'
        } > "${dir}/thr"
        printf '# arch: aarch64\ntotal\tbare\t1547\t15813448\t10222.0\ntotal\tall\t1547\t79305734\t51264.2\n' > "${dir}/ins"
    }
    # expect <rc> <name> <gate> <harness> [<pattern the output must hold>]
    expect() {
        local want="$1" name="$2" got
        set +e; evaluate "${dir}/thr" "${dir}/ins" "$3" "$4" >"${dir}/out" 2>&1; got=$?; set -e
        if [ "${got}" -ne "${want}" ]; then
            echo "  ✗ ${name}: exit ${got}, expected ${want}"; sed 's/^/      /' "${dir}/out"; fails=$((fails + 1))
        elif [ -n "${5:-}" ] && ! grep -q -- "$5" "${dir}/out"; then
            echo "  ✗ ${name}: output lacks '$5'"; sed 's/^/      /' "${dir}/out"; fails=$((fails + 1))
        else
            echo "  ✓ ${name} (exit ${got})"
        fi
    }
    fixture 3200000 21000 900;  expect 0 "the budget met passes" pass pass 'verdict: PASS'
    expect 0 "the Ir/pkt figures are quoted" pass pass 'Ir/pkt bare 10222.0, all 51264.2'
    expect 0 "the target is reported met" pass pass 'target <= 1000: met'
    fixture 3106798 21428 1703.9; expect 0 "the exact pps and RSS bounds pass" pass pass 'verdict: PASS'
    expect 0 "a fetch-all above the target passes, target missed" pass pass 'target <= 1000: missed'
    fixture 3106797 21000 900;  expect 1 "pps below the budget fails" pass pass 'pps 3106797 >= 3106798: FAIL'
    fixture 3200000 21429 900;  expect 1 "library_rss_kib above the budget fails" pass pass '21429 <= 21428 (peak over 20 iterations): FAIL'
    fixture 3200000 -1 900;     expect 1 "an unavailable RSS fails" pass pass 'RSS unavailable'
    fixture 3200000 21000 1704; expect 1 "fetch-all at 1704 ns/pkt fails (strictly below)" pass pass '1704 < 1704: FAIL'
    fixture 3200000 21000 "";   expect 1 "a missing fetch-all row fails" pass pass 'no all row'
    fixture "" 0 900;           expect 1 "a missing bare row fails" pass pass 'no bare row'
    fixture 3200000 21000 900
    expect 1 "a failed instruction gate fails" fail pass 'instruction gate (check_instructions.sh): FAIL - Ir/pkt'
    expect 1 "an instruction gate that could not run fails" error pass 'could not run'
    expect 1 "a failed #555 harness fails" pass fail 'run_throughput_attrs_test.sh: FAIL'
    expect 3 "a skipped gate is incomplete" skipped pass 'verdict: INCOMPLETE (1 of 5'
    expect 3 "a skipped harness is incomplete" pass skipped 'verdict: INCOMPLETE'
    fixture 3106797 21000 900;  expect 1 "a failure outranks a skip" skipped skipped 'verdict: FAIL (1 of 5'
    rm -rf "${dir}"
    if [ "${fails}" -eq 0 ]; then echo "✓ measure_m4_budget self-test: PASS"; return 0; fi
    echo "✗ measure_m4_budget self-test: ${fails} case(s) failed"; return 1
}

# realpath_of FILE — the physical path of FILE, which need not exist yet.
realpath_of() {
    local d
    d="$(cd "$(dirname "$1")" 2>/dev/null && pwd -P)" || return 1
    printf '%s/%s\n' "${d}" "$(basename "$1")"
}

ROLE=""; ITERATIONS=200; OUT=""; DATASETS_OPT=""; CPULIST=""; EXPECT_SHA=""
SKIP_INSTR=0; SKIP_HARNESS=0; EVALUATE=""; EV_INSTR=""; EV_GATE=skipped; EV_HARNESS=skipped
need() {
    if [ $# -lt 2 ] || [ -z "$2" ]; then echo "✗ $1 takes a value" >&2; exit 2; fi
}
while [ $# -gt 0 ]; do
    case "$1" in
        --host-role)         need "$@"; ROLE="$2"; shift 2 ;;
        --iterations)        need "$@"; ITERATIONS="$2"; shift 2 ;;
        --out)               need "$@"; OUT="$2"; shift 2 ;;
        --datasets)          need "$@"; DATASETS_OPT="$2"; shift 2 ;;
        --taskset)           need "$@"; CPULIST="$2"; shift 2 ;;
        --expect-sha256)     need "$@"; EXPECT_SHA="$2"; shift 2 ;;
        --skip-instructions) SKIP_INSTR=1; shift ;;
        --skip-harness)      SKIP_HARNESS=1; shift ;;
        --evaluate)          need "$@"; EVALUATE="$2"; shift 2 ;;
        --instructions)      need "$@"; EV_INSTR="$2"; shift 2 ;;
        --gate)              need "$@"; EV_GATE="$2"; shift 2 ;;
        --harness)           need "$@"; EV_HARNESS="$2"; shift 2 ;;
        --self-test)         self_test; exit $? ;;
        -h|--help)           usage; exit 0 ;;
        *) echo "✗ unknown argument: $1 (see --help)" >&2; exit 2 ;;
    esac
done

if [ -n "${EVALUATE}" ]; then
    case "${EV_GATE}" in pass|fail|error|skipped) ;; *) echo "✗ --gate takes pass, fail, error or skipped" >&2; exit 2 ;; esac
    case "${EV_HARNESS}" in pass|fail|skipped) ;; *) echo "✗ --harness takes pass, fail or skipped" >&2; exit 2 ;; esac
    evaluate "${EVALUATE}" "${EV_INSTR}" "${EV_GATE}" "${EV_HARNESS}"; exit $?
fi

case "${ROLE}" in
    audit) RECORD="audit host (--host-role audit): the M4 reference" ;;
    dev)   RECORD="DEV HOST, NOT the audit host (--host-role dev): not a baseline, never copy it over baseline/perf/throughput.txt" ;;
    '')    echo "✗ --host-role audit|dev is required (see --help)" >&2; exit 2 ;;
    *)     echo "✗ --host-role takes audit or dev (got '${ROLE}')" >&2; exit 2 ;;
esac
case "${ITERATIONS}" in ''|*[!0-9]*|0) echo "✗ --iterations takes a positive integer" >&2; exit 2 ;; esac
if [ -n "${EXPECT_SHA}" ] && ! [[ "${EXPECT_SHA}" =~ ^[0-9a-f]{64}$ ]]; then
    echo "✗ --expect-sha256 takes 64 lowercase hex digits" >&2; exit 2
fi
if [ -z "${OUT}" ]; then
    if [ "${ROLE}" = audit ]; then OUT="${REFERENCE}"; else OUT="${DEV_DEFAULT}"; fi
fi
mkdir -p "$(dirname "${OUT}")"
OUT="$(realpath_of "${OUT}")" || { echo "✗ cannot resolve --out ${OUT}" >&2; exit 2; }
# A dev-host run never lands on the audit host's committed reference.
if [ "${ROLE}" = dev ] && [ "${OUT}" = "$(realpath_of "${REFERENCE}")" ]; then
    echo "✗ --host-role dev refuses to write ${REFERENCE#"${REPO_ROOT}/"}: it holds the audit host's reference" >&2
    exit 2
fi
TASKSET=()
if [ -n "${CPULIST}" ]; then
    command -v taskset >/dev/null 2>&1 || { echo "✗ --taskset needs taskset (util-linux)" >&2; exit 2; }
    taskset -c "${CPULIST}" true 2>/dev/null || { echo "✗ taskset -c ${CPULIST} is refused on this host" >&2; exit 2; }
    TASKSET=(taskset -c "${CPULIST}")
fi

DATASETS="${DATASETS_OPT:-${MMT_TEST_DATASETS:-${REPO_ROOT}/../mmt-test/data-sets}}"
[ -d "${DATASETS}" ] || { echo "✗ mmt-test data-sets not found at: ${DATASETS} (set MMT_TEST_DATASETS or --datasets)" >&2; exit 2; }
DATASETS="$(cd "${DATASETS}" && pwd)"

WORK="$(mktemp -d)"
if [ -n "${MMT_PREFIX:-}" ]; then
    PREFIX="${MMT_PREFIX}"
    trap 'rm -rf "${WORK}"' EXIT
else
    PREFIX="$(mktemp -d /tmp/mmt-m4.XXXXXX)"
    trap 'rm -rf "${WORK}" "${PREFIX}"' EXIT
fi

echo "[1/5] host and dataset"
mapfile -t PCAPS < <(sed -e 's/#.*//' -e '/^[[:space:]]*$/d' "${LIST}")
for rel in "${PCAPS[@]}"; do
    [ -f "${DATASETS}/${rel}" ] || { echo "✗ missing pcap: ${DATASETS}/${rel}" >&2; exit 2; }
done
[ -f "${DATASETS}/${M4_PCAP}" ] || { echo "✗ missing ${DATASETS}/${M4_PCAP}" >&2; exit 2; }
sha="$(sha256sum "${DATASETS}/${M4_PCAP}" | cut -d' ' -f1)"
if [ -n "${EXPECT_SHA}" ] && [ "${sha}" != "${EXPECT_SHA}" ]; then
    echo "✗ ${M4_PCAP} sha256 ${sha} is not the expected ${EXPECT_SHA}: another dataset" >&2; exit 2
fi
commit="$(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
# Dirty: a tracked change other than the output file itself.
root_real="$(cd "${REPO_ROOT}" && pwd -P)"
spec=(.)
case "${OUT}" in "${root_real}/"*) spec+=(":(exclude)${OUT#"${root_real}/"}") ;; esac
if ! status="$(git -C "${REPO_ROOT}" status --porcelain --untracked-files=no -- "${spec[@]}" 2>/dev/null)"; then
    commit="${commit} (tree state unknown)"
elif [ -n "${status}" ]; then
    commit="${commit} (dirty tree)"
fi
echo "    role:    ${ROLE} | commit: ${commit}"
echo "    host:    $(uname -m), $(nproc) cpus, kernel $(uname -r), gcc $(gcc -dumpfullversion)"
echo "    dataset: ${M4_PCAP} sha256 ${sha}"

if [ "${MMT_SDK_PREBUILT:-0}" = "1" ]; then
    echo "[2/5] reusing the SDK installed at ${PREFIX} (MMT_SDK_PREBUILT=1)"
    [ -f "${PREFIX}/dpi/include/mmt_core.h" ] || { echo "✗ no installed SDK under ${PREFIX}" >&2; exit 2; }
else
    echo "[2/5] building + installing the default-profile SDK -> ${PREFIX}"
    make -C "${REPO_ROOT}/sdk" clean >/dev/null 2>&1 || true
    if ! make -C "${REPO_ROOT}/sdk" -j"$(nproc)" MMT_BASE="${PREFIX}" >"${WORK}/build.log" 2>&1 \
       || ! make -C "${REPO_ROOT}/sdk" MMT_BASE="${PREFIX}" install >>"${WORK}/build.log" 2>&1; then
        echo "✗ SDK build/install failed — last lines:" >&2; tail -20 "${WORK}/build.log" >&2; exit 2
    fi
fi

echo "[3/5] capture_perf.sh: ${#PCAPS[@]} pcap(s) x bare attrs8 all, ${ITERATIONS} iterations${CPULIST:+, taskset -c ${CPULIST}}"
if ! MMT_PREFIX="${PREFIX}" MMT_SDK_PREBUILT=1 "${TASKSET[@]}" bash "${SCRIPT_DIR}/capture_perf.sh" \
        --iterations "${ITERATIONS}" --modes "bare attrs8 all" --datasets "${DATASETS}" \
        --record "${RECORD}" --out "${WORK}/throughput.txt" 2>&1 | sed 's/^/    /'; then
    echo "✗ capture_perf.sh failed" >&2; exit 2
fi
[ -s "${WORK}/throughput.txt" ] || { echo "✗ capture_perf.sh wrote nothing" >&2; exit 2; }

GATE=skipped; INSTR_FILE=""
if [ "${SKIP_INSTR}" = 1 ]; then
    echo "[4/5] instruction gate: skipped (--skip-instructions)"
else
    echo "[4/5] instruction gate: check_instructions.sh"
    touch "${WORK}/instr.stamp"
    set +e
    MMT_PREFIX="${PREFIX}" MMT_SDK_PREBUILT=1 bash "${SCRIPT_DIR}/ci/check_instructions.sh" >"${WORK}/instr.log" 2>&1
    rc=$?
    set -e
    sed 's/^/    /' "${WORK}/instr.log"
    case "${rc}" in 0) GATE=pass ;; 1) GATE=fail ;; *) GATE=error ;; esac
    # Only this run's measurement, never one an earlier run left behind.
    if [ -f "${INSTR_ACTUAL}" ] && [ "${INSTR_ACTUAL}" -nt "${WORK}/instr.stamp" ]; then
        cp "${INSTR_ACTUAL}" "${WORK}/instructions.txt"; INSTR_FILE="${WORK}/instructions.txt"
    fi
fi

HARNESS=skipped
if [ "${SKIP_HARNESS}" = 1 ]; then
    echo "[5/5] #555 harness: skipped (--skip-harness)"
else
    echo "[5/5] #555 harness: run_throughput_attrs_test.sh"
    if MMT_SDK_PREBUILT=1 MMT_THRUATTRS_PREFIX="${PREFIX}" \
            bash "${SCRIPT_DIR}/tests/run_throughput_attrs_test.sh" >"${WORK}/harness.log" 2>&1; then
        HARNESS=pass
    else
        HARNESS=fail
    fi
    sed 's/^/    /' "${WORK}/harness.log"
fi

set +e
evaluate "${WORK}/throughput.txt" "${INSTR_FILE}" "${GATE}" "${HARNESS}" >"${WORK}/m4.txt"
verdict=$?
set -e
[ "${verdict}" -ne 2 ] || exit 2
{
    printf '# m4 budget (issue #584): %s | commit: %s | affinity: %s\n' \
        "${RECORD}" "${commit}" "${CPULIST:-none}"
    cat "${WORK}/m4.txt"
} >> "${WORK}/throughput.txt"
cp "${WORK}/throughput.txt" "${OUT}"
echo
sed 's/^# //' "${WORK}/m4.txt"
echo "✓ wrote ${OUT#"${root_real}/"}"
if [ "${ROLE}" = audit ]; then
    echo "  Next: commit it, then run bash scripts/validate-doc-drift.sh — the landing"
    echo "  page quotes the bigFlows bare/attrs8 pps of this file (docs/index.html)."
fi
exit "${verdict}"
