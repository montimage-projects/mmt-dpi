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
