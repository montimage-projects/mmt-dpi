/*
 * test_citrix_ica.c — unit test for Citrix ICA protocol detection (issue #81).
 *
 * Verifies the three detection patterns in src/mmt_tcpip/lib/protocols/proto_citrix.c:
 *   1. ICA handshake: payload_len == 6, header = 0x7F 0x7F 0x49 0x43 0x41 0x00
 *   2. CGP/01: payload_len > 22, header = 0x1a 0x43 0x47 0x50 0x2f 0x30 0x31
 *   3. TcpProxyService: payload contains "Citrix.TcpProxyService"
 *
 * Also verifies that non-Citrix payloads on port 1494 are NOT misclassified.
 *
 * Exit status: 0 = all tests pass, non-zero = failure.
 */
#include <stdio.h>
#include <string.h>

#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"

static int  g_saw_citrix;
static int  g_saw_unknown;
static char g_path[512];

static int classification_handler(const ipacket_t *ipacket, void *user) {
    (void) user;
    const proto_hierarchy_t *ph = ipacket->proto_hierarchy;
    int len = 0, i;
    g_saw_citrix = 0;
    g_saw_unknown = 0;
    g_path[0] = '\0';
    if (ph == NULL) return 0;
    for (i = 0; i < ph->len && i < PROTO_PATH_SIZE; i++) {
        const char *name = get_protocol_name_by_id(ph->proto_path[i]);
        if (name == NULL) name = "?";
        len += snprintf(g_path + len, sizeof(g_path) - len,
                        (i == 0) ? "%s" : ".%s", name);
        if (ph->proto_path[i] == PROTO_CITRIX)   g_saw_citrix   = 1;
        if (ph->proto_path[i] == PROTO_UNKNOWN)   g_saw_unknown  = 1;
        if (len >= (int) sizeof(g_path)) break;
    }
    return 0;
}

/* Build a minimal Ethernet/IPv4/TCP frame carrying the given TCP payload.
 * dst_port specifies the target port (1494 for ICA, 2598 for Citrix RPC,
 * or other ports for negative tests). */
static int build_frame(unsigned char *buf, const unsigned char *payload,
                       int plen, int src_port, int dst_port) {
    int o = 0;
    /* Ethernet header */
    const unsigned char eth[14] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        0x00, 0x06, 0x07, 0x08, 0x09, 0x0a,
        0x08, 0x00 };  /* IPv4 */
    const int ip_total = 20 + 20 + plen;
    /* IP header */
    const unsigned char ip[20] = {
        0x45, 0x00, (unsigned char)((ip_total >> 8) & 0xff),
        (unsigned char)(ip_total & 0xff),
        0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
        10, 0, 0, 1, 10, 0, 0, 2 };
    /* TCP header: SYN+ACK+ACK already established, just payload */
    const unsigned char tcp[20] = {
        (unsigned char)((src_port >> 8) & 0xff),
        (unsigned char)(src_port & 0xff),
        (unsigned char)((dst_port >> 8) & 0xff),
        (unsigned char)(dst_port & 0xff),
        0x00, 0x00, 0x00, 0x01,  /* seq */
        0x00, 0x00, 0x00, 0x01,  /* ack */
        0x50, 0x18, 0xff, 0xff,  /* data offset + PSH+ACK, window */
        0x00, 0x00, 0x00, 0x00 }; /* checksum, urg */
    memcpy(buf + o, eth, 14); o += 14;
    memcpy(buf + o, ip, 20);  o += 20;
    memcpy(buf + o, tcp, 20); o += 20;
    if (plen > 0 && payload != NULL) {
        memcpy(buf + o, payload, plen); o += plen;
    }
    return o;
}

/* Send a packet through MMT and return the classification result. */
static int classify_packet(mmt_handler_t *h, const unsigned char *payload,
                           int plen, int src_port, int dst_port) {
    unsigned char buf[2048];
    struct pkthdr hdr;
    int n;
    memset(&hdr, 0, sizeof(hdr));
    n = build_frame(buf, payload, plen, src_port, dst_port);
    hdr.len = n;
    hdr.caplen = n;
    packet_process(h, &hdr, buf);
    return g_saw_citrix;
}

struct testcase {
    const char *label;
    const unsigned char *payload;
    int            plen;
    int            src_port;
    int            dst_port;
    int            expect_citrix;
};

int main(void) {
    char errbuf[1024];
    mmt_handler_t *h;
    int failures = 0;
    size_t i;

    /* Pattern 1: ICA handshake header (6 bytes) */
    static const unsigned char ica_handshake[6] = {
        0x7F, 0x7F, 0x49, 0x43, 0x41, 0x00
    };

    /* Pattern 2a: CGP/01 header (7 bytes, need >22 total payload) */
    static const unsigned char cgp_header[7] = {
        0x1a, 0x43, 0x47, 0x50, 0x2f, 0x30, 0x31
    };
    /* Pad with dummy data to reach >22 bytes */
    static unsigned char cgp_payload[32];

    /* Pattern 2b: TcpProxyService string (need >22 total payload) */
    static const char tcp_proxy_str[] = "Citrix.TcpProxyService";
    static unsigned char proxy_payload[64];

    /* Non-Citrix payload for negative test */
    static const unsigned char not_citrix[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
        0x1c, 0x1d, 0x1e, 0x1f
    };

    /* Pad CGP payload */
    memset(cgp_payload, 0xAA, sizeof(cgp_payload));
    memcpy(cgp_payload, cgp_header, sizeof(cgp_header));

    /* Pad TcpProxyService payload */
    memset(proxy_payload, 0xBB, sizeof(proxy_payload));
    memcpy(proxy_payload, tcp_proxy_str, sizeof(tcp_proxy_str) - 1);

    struct testcase cases[] = {
        {
            "ICA handshake (6B)",
            ica_handshake, 6, 12345, 1494, 1
        },
        {
            "CGP/01 header (>22B)",
            cgp_payload, 32, 12346, 1494, 1
        },
        {
            "TcpProxyService string (>22B)",
            proxy_payload, sizeof(proxy_payload), 12347, 1494, 1
        },
        {
            "ICA handshake on port 2598 (Citrix RPC)",
            ica_handshake, 6, 12348, 2598, 1
        },
        {
            "Non-Citrix payload (negative test, port 1494)",
            not_citrix, 32, 12349, 1494, 0
        },
        {
            "Non-Citrix payload (negative test, random port)",
            not_citrix, 32, 12350, 8080, 0
        },
        {
            "Empty payload",
            NULL, 0, 12351, 1494, 0
        },
        {
            "Wrong ICA header bytes (negative)",
            (const unsigned char[]){0x00, 0x00, 0x49, 0x43, 0x41, 0x00},
            6, 12352, 1494, 0
        },
    };

    init_extraction();
    h = mmt_init_handler(DLT_EN10MB, 0, errbuf);
    if (h == NULL) {
        fprintf(stderr, "FAIL: mmt_init_handler: %s\n", errbuf);
        close_extraction();
        return 2;
    }
    register_packet_handler(h, 1, classification_handler, NULL);

    printf("== Citrix ICA protocol detection (issue #81) ==\n");
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        int ok = classify_packet(h, cases[i].payload, cases[i].plen,
                                 cases[i].src_port, cases[i].dst_port);
        int pass = (ok == cases[i].expect_citrix);
        printf("  %-40s -> %-40s [%s]\n",
               cases[i].label, g_path, pass ? "PASS" : "FAIL");
        if (!pass) {
            failures++;
            fprintf(stderr,
                "  ✗ %s: expected citrix=%d, got citrix=%d (path='%s')\n",
                cases[i].label, cases[i].expect_citrix, ok, g_path);
        }
    }

    mmt_close_handler(h);
    close_extraction();

    if (failures) {
        printf("\n✗ %d/%zu case(s) failed\n", failures,
               sizeof(cases) / sizeof(cases[0]));
        return 1;
    }
    printf("\n✓ all %zu tests passed\n", sizeof(cases) / sizeof(cases[0]));
    return 0;
}
