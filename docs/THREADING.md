# MMT-DPI Threading Model

This document describes the threading contract for MMT-DPI: what state is
global, what state is per-handler, and the rules a multi-threaded application
must follow to use the library safely.

## Summary of the contract

1. **Initialization before workers.** `init_extraction()` and all protocol /
   plugin (un)registration must complete on a single thread *before* any worker
   thread starts processing packets.
2. **One handler per worker.** Each worker thread owns its own
   `mmt_handler_t` (created with `mmt_init_handler()`). A handler must not be
   shared or used concurrently by more than one thread.
3. **No registration once workers are running.** Registering or unregistering
   protocols/plugins while workers are processing packets is discouraged; if a
   defensive caller does so, the mutations are mutex-guarded (see below) but the
   per-handler snapshot taken at `mmt_init_handler()` time will not reflect the
   change.

Following these rules makes the per-packet hot path completely lock-free.

## Global (process-wide) state

Two registries are global and shared across all handlers/threads:

- `plugin_handlers_list` (`src/mmt_core/src/plugins_engine.c`) - linked list of
  loaded plugin handles.
- `configured_protocols[PROTO_MAX_IDENTIFIER]` and
  `configured_protocols_names_map` (`src/mmt_core/src/packet_processing.c`) -
  the table of protocol descriptors and the name->descriptor index.

These are written only at three kinds of moment:

| Phase            | Functions                                                                 |
|------------------|---------------------------------------------------------------------------|
| Init             | `init_extraction()` (allocates `configured_protocols[]`)                   |
| Plugin load      | `load_plugin()` / `load_plugins()` (append to `plugin_handlers_list`)      |
| (Un)registration | `register_protocol()`, `unregister_protocol_by_id()`, `unregister_protocol_by_name()` |
| Teardown         | `close_plugins()`, `free_registered_protocols()`                           |

### Locking

Each registry has a dedicated `pthread_mutex_t`:

- `plugin_handlers_list_mutex` guards the list mutations in `load_plugin()` and
  `close_plugins()`.
- `configured_protocols_mutex` guards the registry mutations in
  `register_protocol()`, `unregister_protocol_by_id()` and
  `unregister_protocol_by_name()`.

The two locks are never held nested, so there is no lock-ordering hazard:
`load_plugin()` releases the plugin-list lock around `init_proto_fct()`, which is
the call that may take `configured_protocols_mutex` via `register_protocol()`.

These mutexes are taken **only** on the (un)registration/teardown mutation
paths. They are deliberately **not** taken on the per-packet processing hot
path. That is safe because:

- `init_extraction()` allocates the descriptor table once, before workers start.
- `mmt_init_handler()` copies (snapshots) the descriptor pointers from the
  global `configured_protocols[]` into the handler's own
  `mmt_handler->configured_protocols[]` array.
- Packet processing reads only that per-handler snapshot, never the global
  table.

So under the documented init-before-workers ordering, the global registries are
read-only while workers run, and concurrent calls to `mmt_init_handler()` only
perform concurrent reads of the global table - which is safe.

## Per-handler state (not shared)

The following live inside `mmt_handler_t` and are private to the owning thread,
so they need no locking as long as the "one handler per worker" rule holds:

- `mmt_handler->configured_protocols[]` - the per-handler snapshot of protocol
  descriptors plus that handler's session/protocol contexts.
- `sessions_map` (per protocol instance) - session tables.
- `ip_streams` - IP reassembly/stream state.
- `timeout_milestones_map`, packet counters, current-packet scratch state, etc.

## Checklist for multi-threaded use

1. On the main thread: call `init_extraction()` (which loads plugins and
   registers protocols). Wait for it to finish.
2. Create one `mmt_handler_t` per worker thread with `mmt_init_handler()`
   (either on the main thread before spawning, or by each worker before it
   starts processing - both are safe because the global table is read-only by
   then).
3. Each worker feeds packets only to *its own* handler.
4. On shutdown: stop all workers first, free each handler with
   `mmt_close_handler()`, then call the global teardown
   (`close_plugins()` / `free_registered_protocols()`) on a single thread.

## Verification (ThreadSanitizer harness)

The contract above is mechanically verified by a multi-threaded harness
(`tools/phase0/tests/mt_tsan_harness.c`) built and run under ThreadSanitizer.
Because TSan only detects races in code compiled with `-fsanitize=thread`, the
SDK itself is built with the `BUILD=tsan` profile (see `rules/common.mk`) and the
harness is compiled and linked against that instrumented build — including the
dlopen'd `libmmt_tcpip.so` protocol plugin.

The harness has two modes:

- **`replay`** — follows the documented init-before-workers contract:
  `init_extraction()`, all registration, and one *own* `mmt_handler_t` per worker
  are all created on the main thread; then N worker threads run concurrently,
  each replaying the *same* read-only packet array through its own handler (the
  lock-free per-packet hot path). Each worker builds an order-independent
  classification fingerprint; the harness asserts every worker's fingerprint
  equals a single-thread baseline. Replaying a synthetic multi-flow RADIUS pcap
  exercises the per-session RADIUS parser state (issue #23) concurrently across
  threads.
- **`registry-stress`** — spawns N threads that concurrently drive the global
  registry mutation API (`unregister_protocol_by_id` /
  `unregister_protocol_by_name`), hammering `configured_protocols_mutex` directly
  (issue #22). This is intentionally *not* the normal runtime pattern; it drives
  the lock so TSan can confirm the mutex serialises the registry mutations.

Run it locally:

```sh
bash tools/phase0/tests/run_mt_tsan_test.sh
```

The script builds + installs the `BUILD=tsan` SDK into a temporary prefix,
synthesizes the RADIUS pcap, compiles the harness, and runs it under TSan
(`-fno-sanitize-recover=all`, so any detected race aborts). CI runs the same
script in the `tsan-mt-harness` job of `.github/workflows/phase0-baseline.yml`.
