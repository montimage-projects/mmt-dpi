# Decision Log

Append-only log of ambiguities resolved during doc-manager runs.

## 2026-07-21

- Q: README.md lists `simple_packet_handler` and `mmt_online` as examples, but neither exists in `src/examples/`. Which should be documented?
  A (doc-manager): Replace with actual examples: `packet_handler` and `mmt_export_info`.
  Source: confirmed absence via `grep` across `src/examples/`.

- Q: DEVELOPMENT.md lists `cmake` as a prerequisite and `TCP_SEGMENT=1`/`STATIC_LINK=1` as build options, but neither exists in the codebase.
  A (doc-manager): Remove `cmake` from prerequisites; remove `TCP_SEGMENT=1` and `STATIC_LINK=1` from build options table; flag them.
  Source: no CMake in `rules/` or `sdk/Makefile`; no `TCP_SEGMENT`/`STATIC_LINK` in `rules/common.mk`.

- Q: DEVELOPMENT.md says `NDEBUG=1` shows debug messages, but the code defines `-DNDEBUG` by default (which disables debug).
  A (doc-manager): Fix description to: "Define `-DNDEBUG` (default build; disables debug() output)".
  Source: `rules/common.mk:38-42`.

- Q: DEPLOYMENT.md references `MMT_SEC_DTLS_CIPHER_ALLOWLIST` env var, but no code reference was found.
  A (doc-manager): Flag as unverified; remove from env var table.
  Source: grep across `sdk/` and `src/` returned no matches.

- Q: DEPLOYMENT.md says ldconfig file is `mmt.conf`, but code uses `mmt-dpi.conf`.
  A (doc-manager): Fix to `mmt-dpi.conf`.
  Source: `sdk/Makefile:70,117`.

- Q: USER_GUIDE.md says plugins and examples are under `MMT_BASE/dpi/`, but code installs plugins to `$(MMT_BASE)/plugins/` and examples to `$(MMT_BASE)/examples/`.
  A (doc-manager): Fix install layout to show correct paths.
  Source: `rules/common.mk:4-7`.

- Q: USER_GUIDE.md says install script installs `cmake`, but the script does not.
  A (doc-manager): Remove `cmake` from dependency list.
  Source: `install.sh` — no cmake reference.

- Q: Compilation-and-Installation-Instructions.md has wrong git URL (`montimage/mmt-dpi` instead of `montimage-projects/mmt-dpi`), wrong example path (`./examples` instead of `src/examples`), and invalid Homebrew packages (`libpth-dev`, `ldconfig`).
  A (doc-manager): Fix all three issues.

- Q: Add-New-Protocol.md references old paths (`lib/protocols/`, `lib/mmt_common_internal_include.h`, `lib/configured_protocols.c`).
  A (doc-manager): Update to current paths under `src/mmt_tcpip/lib/`.
  Source: confirmed paths via `ls` and `grep`.

- Q: Examples.md references `mmt-sdk/sdk/examples/` as example source location and outdated plugin path (`libmmt_tcpip.so.0.100`).
  A (doc-manager): Update to `src/examples/` and remove hardcoded version from plugin path.

- Q: Data-Types.md has wrong path (`../src/mmt_core/public_include/types_defs.h`), wrong type name (`MMT_STRING_LONG_DATA_POINTER` vs `MMT_STRING_LONG_DATA`), and incorrect descriptions for binary/string types.
  A (doc-manager): Fix path, type name, and descriptions.
  Source: `sdk/include/types_defs.h:169-200, 50-72, 89, 101, 106`.

- Q: MMT-Handler.md says `get_active_session_count` returns `mmt_handler_t*`, but it returns `uint64_t`.
  A (doc-manager): Fix return type description.
  Source: `sdk/include/mmt_core.h:209`.

- Q: MMT-Handler.md has wrong evasion_handler callback signature (missing `void * args` parameter) and wrong constant names (`EVA_IP_FRAG_PACKET` vs `EVA_IP_FRAGMENT_PACKET`).
  A (doc-manager): Fix signature and constant names.
  Source: `sdk/include/mmt_core.h:86-90, 105`.

- Q: MMT-Packet.md shows outdated `pkthdr_t` and `ipacket_struct` (missing many fields).
  A (doc-manager): Update to match current struct definitions.
  Source: `sdk/include/data_defs.h:114-163`.

- Q: Prepare-for-a-new-released-version.md references non-existent `mmt-test/` directories and `wall_e` tool.
  A (doc-manager): Replace with Valgrind-based memory leak check using existing `src/examples/`.

- Q: DNS-protocol.md, HTTP2-protocol.md have outdated development task lists and branch info.
  A (doc-manager): Replace with current protocol description.

- Q: Protocol-Modeling.md contains TBD/???/blablabla placeholder text.
  A (doc-manager): Mark as incomplete and redirect to actual code definitions.

- Q: NDN-protocol.md and NDN-packet-format.md reference non-existent `mmt-test/scripts/ndn.lua`.
  A (doc-manager): Flag as unverified/historical.

- Q: Compiling-mmt-sdk-for-ARM-architecture-by-cross-compiler.md references `ARCH=green-arm` which no longer exists.
  A (doc-manager): Document available targets and suggest cross-compiler approach.

- Q: FTP-design.md has placeholder attribute names `MMT_FTP_XXXX_CMD` and `MMT_FTP_XXX_CODE`.
  A (doc-manager): Flag as placeholder names.

- Q: `docs/Install-mmt-sdk-on-CubieBoard-X.md` is an orphaned doc (not linked from any other doc) referencing mmt-sdk 0.1 for a CubieBoard X. It is not linked from `docs/README.md` or `Developer.md`.
  A (doc-manager): Left in place for historical reference but flagged as orphaned. Not linked from any navigation doc.
