#!/usr/bin/env python3
"""Generate a synthetic high-flow-count pcap to stress the per-flow session store.

The Phase 0 golden set is functionally representative but low on concurrent
flows, so it under-exercises the session table — the single biggest perf lever
(issue #17, replacing the std::map session store with a hash table). This tool
emits a pcap with many distinct TCP 5-tuples and several packets per flow, so
that session *lookups* (not just inserts) dominate the hot path and the
O(log n) -> O(1) change is measurable.

Pure stdlib (struct only) — no scapy/tcpreplay needed, so it is reproducible on
any host and in CI. Output is a classic little-endian pcap, DLT_EN10MB.

Usage:
    tools/phase0/gen_highflow_pcap.py [--flows N] [--packets-per-flow K] [--out FILE]

Defaults: 20000 flows x 4 packets = 80000 packets (~5 MB).
"""
import argparse
import struct

ETH_HLEN = 14
IP_HLEN = 20
TCP_HLEN = 20


def eth_header(src_mac, dst_mac):
    return dst_mac + src_mac + struct.pack("!H", 0x0800)


def ip_header(src_ip, dst_ip, payload_len):
    ver_ihl = (4 << 4) | (IP_HLEN // 4)
    total_len = IP_HLEN + TCP_HLEN + payload_len
    # ttl=64, proto=6 (TCP). Checksum left 0 (parsers under test do not verify it).
    return struct.pack("!BBHHHBBH4s4s",
                       ver_ihl, 0, total_len, 0, 0x4000, 64, 6, 0,
                       src_ip, dst_ip)


def tcp_header(sport, dport, seq):
    data_off = (TCP_HLEN // 4) << 4
    flags = 0x10  # ACK
    return struct.pack("!HHIIBBHHH",
                       sport, dport, seq, 0, data_off, flags, 65535, 0, 0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--flows", type=int, default=20000)
    ap.add_argument("--packets-per-flow", type=int, default=4)
    ap.add_argument("--client-ips", type=int, default=256,
                    help="distinct client IPs; flows beyond this count are "
                         "distinguished by source port. Keeping this small "
                         "models real traffic (few hosts, many flows) so the "
                         "per-flow session table — not IP interning — dominates.")
    ap.add_argument("--out", default="/tmp/highflow.pcap")
    args = ap.parse_args()

    src_mac = b"\x02\x00\x00\x00\x00\x01"
    dst_mac = b"\x02\x00\x00\x00\x00\x02"
    payload = b"\x00" * 8

    with open(args.out, "wb") as f:
        # pcap global header: magic, ver 2.4, tz=0, sigfigs=0, snaplen, DLT_EN10MB(1)
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        ts = 0
        for k in range(args.packets_per_flow):
            for i in range(args.flows):
                # distinct 5-tuple per flow. Spread flows across a small set of
                # client IPs (keeps IP interning cheap) and many source ports,
                # so the per-flow session table is the structure under stress.
                ip_idx = i % args.client_ips
                port_idx = i // args.client_ips
                src_ip = struct.pack("!I", 0x0A000001 + ip_idx)             # 10.0.0.x
                dst_ip = struct.pack("!I", 0xC0A80001)                       # 192.168.0.1
                sport = 1024 + (port_idx % 64000)
                dport = 80
                pkt = (eth_header(src_mac, dst_mac)
                       + ip_header(src_ip, dst_ip, len(payload))
                       + tcp_header(sport, dport, 1000 + k)
                       + payload)
                ts += 1
                f.write(struct.pack("<IIII", ts // 1000000, ts % 1000000,
                                    len(pkt), len(pkt)))
                f.write(pkt)
    total = args.flows * args.packets_per_flow
    print("wrote %s: %d flows x %d pkts = %d packets"
          % (args.out, args.flows, args.packets_per_flow, total))


if __name__ == "__main__":
    main()
