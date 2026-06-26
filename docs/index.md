---
layout: default
title: MMT-DPI
description: Deep packet inspection for 200+ protocols, as a C library
---

# Deep packet inspection for 200+ protocols, in C

MMT-DPI classifies network traffic and extracts typed, named attributes —
IPs, ports, headers, payload fields — at line rate. Add new protocols as
plugins without touching the core.

[**Get started &rarr;**](#quick-start) · [User Guide](USER_GUIDE.md) · [GitHub](https://github.com/montimage-projects/mmt-dpi)

---

## The problem

Most traffic-analysis stacks force a trade-off: fixed-protocol tools can't
follow traffic as it moves to QUIC, HTTP/2, and 5G control planes — and
hand-rolled parsers turn every new protocol into a byte-offset rewrite that
breaks under malformed or fragmented input.

MMT-DPI gives you a classification-and-extraction engine you query by name,
plus a plugin interface for the protocols you add yourself.

## How it works

<div class="mermaid">
graph LR
    A[Packet / pcap / live capture] --> B[mmt_core engine]
    B --> C{Protocol<br/>classification}
    C --> D[Attribute extraction<br/>by name]
    C --> E[Session tracking<br/>flow stats]
    D --> F[Your handler callback]
    E --> F
    G[Protocol plugins<br/>TCP/IP · HTTP2 · QUIC · DNS · 5G NAS/NGAP] -. extend .-> C
</div>

You register the attributes you care about by `(protocol, field)` name, attach
a packet handler, and feed packets in. The engine classifies each packet,
extracts the registered fields, and updates per-session statistics before
calling back.

## Key features

| Feature | What you get |
|---|---|
| 200+ protocols | Automatic classification across the TCP/IP stack and application layer |
| Named attribute extraction | Pull protocol fields by `(proto, field)` — no manual offset math |
| Session tracking | Per-flow RTT, retransmissions, byte/packet counts |
| Plugin architecture | Add protocols as modular plugins, no core changes |
| 5G/LTE support | NAS, S1AP, NGAP, GTPv2, Diameter for mobile-network monitoring |
| Modern transports | HTTP/2, QUIC (RFC 9000), DTLS, MQTT, OSPF, RADIUS, and more |

## Quick start

Install on Linux (Debian/Ubuntu, Fedora/RHEL, Arch, Alpine, openSUSE):

```bash
curl -sSL https://raw.githubusercontent.com/montimage-projects/mmt-dpi/main/install.sh | bash
```

Or build from source:

```bash
git clone https://github.com/montimage-projects/mmt-dpi.git
cd mmt-dpi/sdk && make -j$(nproc) && sudo make install
```

Extract an attribute in a handler:

```c
#include "mmt_core.h"

void on_packet(const ipacket_t *ipacket, void *args) {
    uint32_t *len = get_attribute_extracted_data_by_name(ipacket, "META", "PACKET_LEN");
    if (len) printf("packet size: %u\n", *len);
}

int main(void) {
    init_extraction();
    mmt_handler_t *h = mmt_init_handler(DLT_EN10MB, 0, NULL);
    register_extraction_attribute_by_name(h, "META", "PACKET_LEN");
    register_packet_handler(h, 1, on_packet, NULL);
    // ... feed packets from pcap or live capture ...
    mmt_close_handler(h);
    close_extraction();
}
```

## Documentation

- [User Guide](USER_GUIDE.md) — install, run the examples, write your first program
- [Adding New Protocols](Add-New-Protocol.md)
- [Protocol Stack Architecture](Protocol-Stack.md)
- [Handler Interface](MMT-Handler.md) · [Session Management](MMT-Session.md) · [Memory Management](Memory-Management.md)
- [Full documentation index](README.md)

## Built with MMT-DPI

MMT-DPI underpins peer-reviewed research and Montimage products in DPI, IoT
monitoring, 5G security, and intrusion detection — including **5GReplay**
(ARES 2021) and IoT security-monitoring frameworks on Fed4Fire+. See the
[Related Publications](README.md#related-publications) list.

## Get started

```bash
curl -sSL https://raw.githubusercontent.com/montimage-projects/mmt-dpi/main/install.sh | bash
```

[**User Guide &rarr;**](USER_GUIDE.md) · [**Examples &rarr;**](https://github.com/montimage-projects/mmt-dpi/tree/main/src/examples) · Apache-2.0 Licensed

<script type="module">
  import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs';
  mermaid.initialize({ startOnLoad: true, theme: 'neutral' });
</script>
