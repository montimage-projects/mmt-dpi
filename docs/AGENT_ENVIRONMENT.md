# Agent Environment Notes

This document describes the build/test environment an automated agent (or a
fresh contributor) needs to install, configure, build, and test this
repository without unwritten context. Everything here is derived from the
repository itself; the authoritative sources are:

| Source of truth | What it defines |
|-----------------|-----------------|
| `rules/common.mk` | Compiler flags, `MMT_BASE`, `BUILD=asan`/`tsan`, `ENABLESEC`, debug/valgrind toggles |
| `rules/common-linux.mk` | Linux link rules, release hardening, `ENABLESEC` engines |
| `sdk/Makefile` | Build entry point, `install`/`test` targets, default `MMT_BASE` |
| `tests/run_all_tests.sh` | Master test runner and the 8 standalone suites |

## 1. Toolchain Requirements

Only **Linux** is supported (macOS/Windows are not).

```bash
sudo apt-get update
sudo apt-get install -y build-essential gcc make libxml2-dev libpcap-dev libnghttp2-dev bash git file pkg-config
```

| Package | Why it is needed |
|---------|------------------|
| `gcc`, `make` | The whole build (`rules/common-linux.mk:47` enables LTO for GCC only) |
| `libpcap-dev` | Examples that read pcap files (`src/examples/`) |
| `libxml2-dev` | Only needed with `ENABLESEC=1` (`rules/common.mk:76-84`) |
| `libnghttp2-dev` | Optional at build time — the Makefile auto-detects its absence and keeps building (`rules/common.mk:56-74`) |
| `bash` | Test scripts are bash (`tests/run_all_tests.sh`) |

Notes:

- Clang is available via `make ARCH=linux-clang`; icc via `ARCH=linux-icc`
  (rule files in `rules/arch-*.mk`). GCC is the default and best-tested path.
- A C++ compiler (`g++`, pulled in by `build-essential`) is required because
  shared libraries are linked with `$(CXX)` (`rules/common-linux.mk:161`).

## 2. Building

There is no top-level Makefile. The build entry point is `sdk/Makefile`:

```bash
make -C sdk -j$(nproc)
```

Exit code `0` = green build. Warnings in the output (e.g. from vendored asn1c
code) are informational; extra diagnostic warnings are deliberately not
`-Werror` (`rules/common.mk:239-253`), so they never fail the build.

The build produces shared libraries and static archives under `sdk/lib/`
(`libmmt_core.so`, `libmmt_tcpip.so`, `libmmt_tmobile.so`,
`libmmt_business_app.so`, `libmmt_tdicom.so`, plus matching `.a` files),
copies public headers under `sdk/include/`, examples under `sdk/examples/`,
and tools under `sdk/bin/`. It does **not** require root and does **not**
install anything.

Clean rebuild if needed:

```bash
make -C sdk clean && make -C sdk -j$(nproc)
```

### Useful build flags

All flags are passed as make variables, e.g. `make -C sdk DEBUG=1`.

| Flag | Effect | Source |
|------|--------|--------|
| `DEBUG=1` | `-g` instead of `-O3`; asserts/debug() stay active | `rules/common.mk:87-93` |
| `NDEBUG=1` | Default behavior kept explicit (`-DNDEBUG`) | `rules/common.mk:38-43` |
| `SHOWLOG=1` | Show `MMT_LOG()` output (`-DDEBUG -DHTTP_PARSER_STRICT=1`) | `rules/common.mk:159-166` |
| `VALGRIND=1` | Valgrind-friendly instrumentation | `rules/common.mk:94-98` |
| `TUNE=native` | Opt-in `-march=native` (unsafe for redistributed binaries — off by default) | `rules/common-linux.mk:89-97` |
| `VERBOSE=1` | Print full compile commands | `rules/common.mk:21-24` |

## 3. Testing

```bash
bash tests/run_all_tests.sh
```

Expected result: **8/8 suites pass**, total runtime roughly 20–30 s on a
typical development machine. Exit code `0` on success, `1` on any failure.
The suite list lives in `DEFAULT_SUITES` (`tests/run_all_tests.sh:44-53`):
`hashmap`, `memory`, `hexdump`, `mmt_utils`, `mmt_inet_ntop`, `avltree`,
`citrix_ica_detection`, `http_header_case`.

Key property for agents: these suites are **standalone**. Each suite's
`run_tests.sh` compiles its test directly against sources under `src/` with
plain `gcc` — no prior build, no install, no `sudo` needed. You can run one
suite by passing its directory name:

```bash
bash tests/run_all_tests.sh hashmap memory   # subset
```

## 4. `MMT_BASE` Install-Prefix Behavior

`MMT_BASE` is the install prefix. Defaults:

- `rules/common.mk:3` — `MMT_BASE ?=/opt/mmt` (used by compile-time paths)
- `sdk/Makefile:8-13` — when `MMT_BASE` is unset, `make install` targets
  `/opt/mmt` and sets `NEED_ROOT_PERMISSION := 1` (writes
  `/etc/ld.so.conf.d/mmt-dpi.conf` and runs `ldconfig`)

### The `make test` trap

`sdk/Makefile`'s `test` target (`sdk/Makefile:239-242`) compiles the
`proto_attributes_iterator` example **from the installed prefix**:

```
$(MMT_EXAMS)/proto_attributes_iterator.c  # = $(MMT_BASE)/examples/...
-I $(MMT_INC) -L $(MMT_LIB)               # = $(MMT_BASE)/dpi/{include,lib}
```

So a bare `make -C sdk test` silently depends on a previous
`sudo make install` into `/opt/mmt` — without it, the target fails to find
the example source or links against stale libraries. This is why the agent
test command of record is `bash tests/run_all_tests.sh`, which has no such
hidden dependency.

### Isolating with `MMT_BASE`

To exercise the real install flow without root, point `MMT_BASE` somewhere
writable — everything (build artifacts and install destination) stays inside
your sandbox directory:

```bash
make -C sdk MMT_BASE=/tmp/mmt-sandbox -j$(nproc)
make -C sdk MMT_BASE=/tmp/mmt-sandbox install
# libraries land in /tmp/mmt-sandbox/dpi/lib, headers in .../dpi/include,
# plugin .so copies in /tmp/mmt-sandbox/plugins
LD_LIBRARY_PATH=/tmp/mmt-sandbox/dpi/lib <your-test-binary>
```

One subtlety: the plugin repository path is baked into compiled code as
`PLUGINS_REPOSITORY_OPT` (`-DPLUGINS_REPOSITORY_OPT=\"$(MMT_PLUGINS)\")`,
see `rules/common.mk:30`). If you change `MMT_BASE` between building and
installing, `sdk/Makefile:28-29` removes `plugins_engine.o` so it gets
recompiled with the new path. Keep `MMT_BASE` identical across your
build/install invocations to avoid surprises.

## 5. Sanitizer Build Profiles

Two verification profiles exist in `rules/common.mk` (both add flags to
`CFLAGS` and `CXXFLAGS` so they reach the shared-library link lines):

### `BUILD=asan` — AddressSanitizer + UBSan

Defined at `rules/common.mk:100-127`. Verification vehicle for memory-safety
hardening: catches OOB reads/writes, use-after-free, and UB on untrusted
packet input.

```bash
make -C sdk BUILD=asan MMT_BASE=/tmp/mmt-asan -j$(nproc)
make -C sdk BUILD=asan MMT_BASE=/tmp/mmt-asan install
# Run an instrumented example through crafted pcaps:
LD_PRELOAD=$(gcc -print-file-name=libasan.so) \
  ASAN_OPTIONS=detect_leaks=0 \
  LD_LIBRARY_PATH=/tmp/mmt-asan/dpi/lib \
  /tmp/mmt-asan/examples/extract_all -t crafted.pcap
```

Leak detection is left to Valgrind; ASan here targets memory safety/UB.

### `BUILD=tsan` — ThreadSanitizer

Defined at `rules/common.mk:129-157`. Verification vehicle for thread-safety
work (registry mutexes, per-session state). TSan only sees races in code
compiled with `-fsanitize=thread`, so both the SDK and the multi-threaded
harness must be built with this profile — see
`tools/phase0/tests/run_mt_tsan_test.sh` for the full pipeline and
[THREADING.md](./THREADING.md) for what it verifies.

```bash
make -C sdk BUILD=tsan MMT_BASE=/tmp/mmt-tsan -j$(nproc)
make -C sdk BUILD=tsan MMT_BASE=/tmp/mmt-tsan install
```

In both profiles the release-hardening block (LTO, FORTIFY, stack protector,
RELRO — `rules/common-linux.mk:51-103`) is automatically disabled, and the
`-Wl,-z,defs` self-containedness guard is skipped because sanitizer runtime
symbols are intentionally left undefined (`rules/common-linux.mk:126-138`).

## 6. `ENABLESEC=1` Security Engines Flag

`ENABLESEC` gates two optional libraries — `libmmt_security` and
`libmmt_fuzz` — which are otherwise not built at all:

- Object/header selection: `rules/common.mk:189-191, 213-216, 279-288`
- Link rules and libxml2 wiring: `rules/common-linux.mk:6-12, 139-142, 150-154, 187-203`
- Install symlinks for both engines: `sdk/Makefile:46-47, 109-110`

Usage (requires `libxml2-dev`):

```bash
make -C sdk ENABLESEC=1 -j$(nproc)
```

Without the flag those sources are skipped entirely, so a missing libxml2 is
only fatal when `ENABLESEC=1`.

## 7. Quick Verification Checklist

Run this after setting up a fresh environment; all four commands must succeed:

```bash
make -C sdk -j$(nproc)          # exit 0, green build (~1–2 min)
bash tests/run_all_tests.sh     # 8/8 suites PASSED, exit 0 (~25 s)
make -C sdk ENABLESEC=1 -j$(nproc)   # exit 0 (optional engines build)
make -C sdk BUILD=asan MMT_BASE=/tmp/mmt-asan -j$(nproc)   # exit 0 (sanitizer profile)
```

If any of these fails, fix the environment before attempting code changes —
upstream tasks assume this baseline is green.
