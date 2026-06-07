# Externally-updatable IP-range / port attribution (M9)

*Part of the MMT-DPI Master Improvement Plan — Phase 7 (M9, issue #26).*

Historically MMT-DPI shipped ~10,000 IP ranges and a fixed set of L4 ports
**hardcoded** in the C sources (`mmt_tcpip_classif_utils.c`,
`mmt_tcpip_plugin_internal.c`). Refreshing a stale CDN/cloud range or adding a
port hint meant editing C and rebuilding the library.

M9 makes this attribution data **externally updatable**. The compiled-in tables
remain the bundled **default/fallback**, and operators can additionally supply
plain-text data files whose entries are merged on top of the built-in tables at
initialization time.

> **No behaviour change by default.** When the environment variables below are
> unset (the default, and what CI uses), nothing extra is loaded and
> classification is byte-identical to the compiled-in baseline. This is gated by
> the golden classification fingerprint in CI.

## IP-range attribution — `MMT_DPI_IP_RANGES_FILE`

```
export MMT_DPI_IP_RANGES_FILE=/etc/mmt/ip_ranges.txt
```

Each line is `<A.B.C.D>/<prefixlen>  <PROTOCOL>`:

```
# comments and blank lines are ignored
142.250.0.0/16    GOOGLE
13.32.0.0/15      AMAZON
9              # numeric protocol id is also accepted (rename-proof)
```

* `prefixlen` must be in `[1, 30]` (it indexes the per-prefix AVL trees).
* `<PROTOCOL>` is a registered protocol name (resolved via
  `get_protocol_id_by_name`) or a bare numeric protocol id.
* Rules **extend** the AVL trees; invalid lines are skipped with a warning.

See [`data/ip_ranges.example.txt`](../data/ip_ranges.example.txt).

## Port hints — `MMT_DPI_PORT_MAP_FILE`

```
export MMT_DPI_PORT_MAP_FILE=/etc/mmt/port_map.txt
```

Each line is `<tcp|udp>  <port>  <PROTOCOL>`:

```
tcp 8443 SSL
udp 5353 DNS
```

These are consulted **only after** the compiled-in port switch returns no match,
so they never override a built-in mapping.

See [`data/port_map.example.txt`](../data/port_map.example.txt).

### Port attribution is a hint, not a verdict

Port-based attribution is the **weakest** signal in the pipeline and is already
demoted to a *hint of last resort*:

* Callers (`proto_tcp.c`, `proto_udp.c`) consult the port guess **only after**
  payload-signature classification *and* IP-range classification have failed.
* It is gated behind `enable_port_classify()`, which is **OFF by default**
  (`mmt_init_handler` sets `port_classify = 0`).

Sourcing extra ports from an updatable file keeps that weak signal out of the
compiled-in tables and lets operators refresh it without a rebuild. Fully
gating *every* port guess behind an explicit payload-signature confirmation
step is tracked as follow-up work (see the issue #26 PR).

## Threading / lifecycle

Both files are loaded once, single-threaded, during
`init_extraction()` → `init_tcpip_plugin()`, before any worker thread exists,
and are only read afterwards on the hot path. This respects the threading
contract in [`THREADING.md`](THREADING.md) (init-time writers, hot-path
readers). Heap allocations are released by `_free_proto_avltrees()` (IP ranges)
and `cleanup_tcpip_plugin()` (port hints).
