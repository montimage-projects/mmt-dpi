/*
 * ip_unaligned_header_test — regression test for issue #57
 * (UBSan misaligned-access on struct iphdr/tcphdr/udphdr dereferences over the
 *  byte-aligned packet buffer).
 *
 * Root cause: the IP/L4 classification path forms header pointers by casting
 * "&ipacket->data[offset]" (a char-aligned capture buffer) to struct
 * iphdr/tcphdr/udphdr and dereferences multi-byte fields directly. When the
 * header does not land on its natural 2-/4-byte boundary this is a misaligned
 * access — undefined behaviour that aborts under -fsanitize=alignment.
 *
 * The SDK copies each captured packet into an mmt_malloc'd (16-byte aligned)
 * buffer before classification, so a standard 14-byte Ethernet header places
 * the IPv4 header at a 2-byte-aligned (NOT 4-byte-aligned) address. That makes
 * the misalignment DETERMINISTIC here: before the fix this test aborts inside
 * mmt_iph_is_fragmented (proto_ip.c) under the BUILD=asan library; after the
 * fix it runs clean and classifies correctly.
 *
 * It drives the full public packet path (mmt_init_handler + packet_process) so
 * it exercises the real IP / TCP / UDP-DNS / fragment-reassembly code
 * (including ip_fragment_key / ip_dgram_update on the fragment).
 *
 * The library it links against must be built with BUILD=asan; the runner script
 * (run_ip_unaligned_header_test.sh) takes care of that. With
 * -fno-sanitize-recover=all any sanitizer hit aborts the process, so a clean
 * exit 0 with all assertions passing is the success condition.
 *
 * Build (see run_ip_unaligned_header_test.sh):
 *   gcc -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
 *       -o ip_unaligned_header_test ip_unaligned_header_test.c \
 *       -I<prefix>/dpi/include -L<prefix>/dpi/lib -lmmt_core -ldl -lpcap
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <pcap.h>            /* DLT_EN10MB */

#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"

typedef unsigned char u_char;

static int g_failures = 0;
static int g_checks   = 0;

#define CHECK(cond, msg) do {                                        \
        g_checks++;                                                  \
        if (cond) {                                                  \
            printf("  PASS: %s\n", (msg));                           \
        } else {                                                     \
            printf("  FAIL: %s\n", (msg));                           \
            g_failures++;                                            \
        }                                                            \
    } while (0)

/* Lower-cased dotted protocol path of the last classified packet. */
static char g_last_path[512];

static int packet_handler(const ipacket_t *ipacket, void *user_args) {
    const proto_hierarchy_t *ph = ipacket->proto_hierarchy;
    int len = 0, i;
    (void) user_args;
    g_last_path[0] = '\0';
    if (ph == NULL || ph->len <= 0)
        return 0;
    for (i = 0; i < ph->len && i < PROTO_PATH_SIZE; i++) {
        const char *name = get_protocol_name_by_id(ph->proto_path[i]);
        int n;
        if (name == NULL) name = "?";
        n = snprintf(g_last_path + len, sizeof(g_last_path) - len,
                     (i == 0) ? "%s" : ".%s", name);
        if (n < 0 || n >= (int)(sizeof(g_last_path) - len)) break;
        len += n;
    }
    return 0;
}

/* --- packet builders --------------------------------------------------- */

static void put_be16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v & 0xff; }

/* Write a 14-byte Ethernet header (ethertype IPv4). */
static int put_eth(uint8_t *b) {
    static const uint8_t dst[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
    static const uint8_t src[6] = {0x66,0x77,0x88,0x99,0xaa,0xbb};
    memcpy(b, dst, 6);
    memcpy(b + 6, src, 6);
    put_be16(b + 12, 0x0800);
    return 14;
}

/* Write a 20-byte IPv4 header (ihl=5). frag_off is passed raw (host->be). */
static int put_ip4(uint8_t *b, uint8_t proto, uint16_t tot_len, uint16_t frag_off) {
    memset(b, 0, 20);
    b[0]  = 0x45;                 /* version 4, ihl 5 */
    b[1]  = 0x00;                 /* tos */
    put_be16(b + 2, tot_len);     /* total length */
    put_be16(b + 4, 0x1234);      /* id */
    put_be16(b + 6, frag_off);    /* flags + fragment offset */
    b[8]  = 64;                   /* ttl */
    b[9]  = proto;                /* protocol */
    /* checksum left 0 (MMT does not validate it) */
    b[12] = 10; b[13] = 0; b[14] = 0; b[15] = 1;   /* saddr 10.0.0.1 */
    b[16] = 10; b[17] = 0; b[18] = 0; b[19] = 2;   /* daddr 10.0.0.2 */
    return 20;
}

/* Feed one packet through the full classification path. */
static void run_packet(mmt_handler_t *h, const uint8_t *data, uint32_t caplen) {
    struct pkthdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.ts.tv_sec  = 1;
    hdr.ts.tv_usec = 0;
    hdr.caplen     = caplen;
    hdr.len        = caplen;
    /* If the misalignment regresses, the BUILD=asan library aborts here. */
    packet_process(h, &hdr, data);
}

int main(void) {
    char errbuf[1024];
    mmt_handler_t *h;
    uint8_t pkt[256];
    int off;

    init_extraction();
    h = mmt_init_handler(DLT_EN10MB, 0, errbuf);
    if (h == NULL) {
        fprintf(stderr, "mmt_init_handler failed: %s\n", errbuf);
        close_extraction();
        return 2;
    }
    register_packet_handler(h, 1, packet_handler, NULL);

    printf("issue #57: unaligned IP/L4 header classification under ASan/UBSan\n");

    /* 1. IPv4 + ICMP echo request: exercises mmt_iph_is_fragmented + the IP
     *    classification path (the original abort site, proto_ip.c:1406). */
    off  = put_eth(pkt);
    off += put_ip4(pkt + off, 1 /*ICMP*/, 20 + 8, 0);
    pkt[off++] = 8;  pkt[off++] = 0;            /* type/code echo request */
    put_be16(pkt + off, 0xf7ff); off += 2;      /* checksum */
    put_be16(pkt + off, 1); off += 2;           /* id */
    put_be16(pkt + off, 1); off += 2;           /* seq */
    run_packet(h, pkt, off);
    CHECK(strstr(g_last_path, "ip") != NULL, "IPv4+ICMP packet classified as IP");

    /* 2. IPv4 + TCP SYN: exercises the TCP header view (packet->tcp->doff,
     *    build_ipv4_session_key tcph, http syn check). */
    off  = put_eth(pkt);
    off += put_ip4(pkt + off, 6 /*TCP*/, 20 + 20, 0);
    put_be16(pkt + off, 12345); off += 2;       /* sport */
    put_be16(pkt + off, 80);    off += 2;        /* dport */
    memset(pkt + off, 0, 8); off += 8;           /* seq + ack */
    pkt[off++] = 0x50;                            /* data offset 5 (<<4) */
    pkt[off++] = 0x02;                            /* flags: SYN */
    put_be16(pkt + off, 0xffff); off += 2;       /* window */
    put_be16(pkt + off, 0);      off += 2;        /* checksum */
    put_be16(pkt + off, 0);      off += 2;        /* urg ptr */
    run_packet(h, pkt, off);
    CHECK(strstr(g_last_path, "tcp") != NULL, "IPv4+TCP packet classified through TCP");

    /* 3. IPv4 + UDP + DNS query: exercises the UDP header view and the
     *    get_u16/get_u32 payload accessors (proto_dns/proto_nfs etc.). */
    off  = put_eth(pkt);
    {
        int udp_start;
        off += put_ip4(pkt + off, 17 /*UDP*/, 20 + 8 + 12 + 5, 0);
        udp_start = off;
        put_be16(pkt + off, 33333); off += 2;    /* sport */
        put_be16(pkt + off, 53);    off += 2;     /* dport (DNS) */
        put_be16(pkt + off, 8 + 12 + 5); off += 2;/* udp length */
        put_be16(pkt + off, 0);     off += 2;     /* checksum */
        /* DNS header (id, flags=query, qd=1, others 0) */
        put_be16(pkt + off, 0x1a2b); off += 2;
        put_be16(pkt + off, 0x0100); off += 2;
        put_be16(pkt + off, 1);      off += 2;
        put_be16(pkt + off, 0);      off += 2;
        put_be16(pkt + off, 0);      off += 2;
        put_be16(pkt + off, 0);      off += 2;
        /* a single label "a", root, type, class (kept short) */
        pkt[off++] = 1; pkt[off++] = 'a'; pkt[off++] = 0;
        pkt[off++] = 0; pkt[off++] = 1;
        (void) udp_start;
    }
    run_packet(h, pkt, off);
    CHECK(strstr(g_last_path, "udp") != NULL, "IPv4+UDP/DNS packet classified through UDP");

    /* 4. IPv4 first fragment (MF set): exercises mmt_iph_is_fragmented(true),
     *    ip_fragment_key() and ip_dgram_update() on a misaligned header. */
    off  = put_eth(pkt);
    off += put_ip4(pkt + off, 6 /*TCP, payload irrelevant*/, 20 + 24, 0x2000 /*MF*/);
    memset(pkt + off, 0x5a, 24); off += 24;
    run_packet(h, pkt, off);
    CHECK(strstr(g_last_path, "ip") != NULL, "IPv4 fragment classified as IP (reassembly path ran)");

    mmt_close_handler(h);
    close_extraction();

    printf("\n%d checks, %d failures\n", g_checks, g_failures);
    if (g_failures != 0) {
        printf("RESULT: FAIL\n");
        return 1;
    }
    printf("RESULT: PASS\n");
    return 0;
}
