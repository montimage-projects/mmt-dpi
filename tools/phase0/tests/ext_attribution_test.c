/*
 * ext_attribution_test — unit test for the externally-updatable IP-range / port
 * attribution loaders (issue #26, M9).
 *
 * M9 moves IP-range/port attribution out of the compiled-in tables and into
 * optional, operator-supplied data files. The compiled-in tables remain the
 * default/fallback, so with no data file the classification is byte-identical
 * to the baseline (that invariant is gated separately by the golden
 * classification fingerprint). This test pins down the loaders themselves:
 *
 *   mmt_tcpip_load_ip_ranges_file(path) — parse CIDR->proto rules into the
 *                                         IP-range AVL trees
 *   mmt_tcpip_load_port_map_file(path)  — parse "<tcp|udp> <port> <proto>" rules
 *   _find_proto_id_by_address(src,dst)  — the host-order AVL lookup, so we can
 *                                         observe that a loaded range takes effect
 *
 * The loaders are exported (non-static) from libmmt_tcpip but live in an
 * internal header that is not installed, so they are re-declared here and the
 * test links libmmt_tcpip directly. A clean exit 0 with every CHECK passing is
 * the success condition.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include <pcap.h>            /* DLT_EN10MB */

#include "mmt_core.h"

/* Loaders / lookup under test — exported from libmmt_tcpip. */
extern int mmt_tcpip_load_ip_ranges_file(const char *path);
extern int mmt_tcpip_load_port_map_file(const char *path);
extern int _find_proto_id_by_address(uint32_t ip_src, uint32_t ip_dst);

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond, msg) do {                                         \
        g_checks++;                                                   \
        if (cond) {                                                   \
            printf("  PASS: %s\n", (msg));                            \
        } else {                                                      \
            printf("  FAIL: %s\n", (msg));                            \
            g_failures++;                                             \
        }                                                             \
    } while (0)

/* Write `content` to a unique temp file; returns a malloc'd path (caller frees). */
static char *write_tmp(const char *content)
{
    char *path = strdup("/tmp/mmt_ext_attr_XXXXXX");
    int fd = mkstemp(path);
    if (fd < 0) {
        perror("mkstemp");
        free(path);
        return NULL;
    }
    FILE *fp = fdopen(fd, "w");
    fputs(content, fp);
    fclose(fp);
    return path;
}

/* 198.51.100.0/24 (TEST-NET-2, RFC 5737) and 203.0.113.0/24 (TEST-NET-3) are
 * reserved-for-documentation ranges that never appear in the bundled table. */
#define TESTNET2_HOST 0xC6336405u   /* 198.51.100.5 in host byte order */
#define TESTNET3_HOST 0xCB007105u   /* 203.0.113.5   in host byte order */

static void test_ip_ranges(void)
{
    printf("[1] external IP-range loading\n");

    uint32_t http_id = get_protocol_id_by_name("HTTP");
    CHECK(http_id != 0, "HTTP protocol id resolves (registry initialised)");

    /* The documentation ranges are unknown before any file is loaded. */
    CHECK(_find_proto_id_by_address(TESTNET2_HOST, 0) == -1,
          "198.51.100.5 unknown before loading (built-in fallback only)");

    /* A non-existent file is reported as an error, not a silent success. */
    CHECK(mmt_tcpip_load_ip_ranges_file("/no/such/mmt/ranges.txt") == -1,
          "missing IP-range file returns -1");

    /* A file with comments, blanks and malformed lines loads only the valid
     * rule and reports the exact count. */
    char *f1 = write_tmp(
        "# M9 external IP ranges (issue #26)\n"
        "\n"
        "198.51.100.0/24   HTTP\n"
        "999.1.2.3/24      HTTP        # invalid address -> skipped\n"
        "203.0.113.0/40    HTTP        # prefix out of range -> skipped\n"
        "203.0.113.0/24    NOSUCHPROTO # unknown protocol -> skipped\n"
        "10.0.0.0          HTTP        # missing /prefix -> skipped\n");
    CHECK(f1 != NULL, "temp IP-range file created");
    int n1 = mmt_tcpip_load_ip_ranges_file(f1);
    CHECK(n1 == 1, "exactly one valid IP-range rule loaded (others skipped)");

    /* The loaded /24 now resolves to HTTP for an address inside it ... */
    CHECK((uint32_t) _find_proto_id_by_address(TESTNET2_HOST, 0) == http_id,
          "198.51.100.5 now attributed to HTTP via the loaded range");
    /* ... and also when it appears as the destination address. */
    CHECK((uint32_t) _find_proto_id_by_address(0, TESTNET2_HOST) == http_id,
          "loaded range also matches on the destination address");
    /* An address outside the loaded range is still unknown. */
    CHECK(_find_proto_id_by_address(TESTNET3_HOST, 0) == -1,
          "203.0.113.5 (not loaded) stays unknown");

    /* A bare numeric protocol id is accepted as a fallback token. */
    char numbuf[64];
    snprintf(numbuf, sizeof(numbuf), "203.0.113.0/24 %u\n", http_id);
    char *f2 = write_tmp(numbuf);
    int n2 = mmt_tcpip_load_ip_ranges_file(f2);
    CHECK(n2 == 1, "numeric protocol-id token accepted");
    CHECK((uint32_t) _find_proto_id_by_address(TESTNET3_HOST, 0) == http_id,
          "203.0.113.5 attributed via numeric proto-id rule");

    if (f1) { unlink(f1); free(f1); }
    if (f2) { unlink(f2); free(f2); }
}

static void test_port_map(void)
{
    printf("[2] external port-map loading\n");

    CHECK(mmt_tcpip_load_port_map_file("/no/such/mmt/ports.txt") == -1,
          "missing port-map file returns -1");

    char *f = write_tmp(
        "# M9 external port hints (issue #26)\n"
        "tcp 9999 HTTP\n"
        "udp 8888 DNS\n"
        "sctp 1 HTTP    # unsupported L4 -> skipped\n"
        "tcp 70000 HTTP # port out of range -> skipped\n"
        "tcp 1234 NOPE  # unknown protocol -> skipped\n"
        "garbage line\n");
    CHECK(f != NULL, "temp port-map file created");
    int n = mmt_tcpip_load_port_map_file(f);
    CHECK(n == 2, "exactly two valid port rules loaded (others skipped)");

    if (f) { unlink(f); free(f); }
}

int main(void)
{
    printf("== ext_attribution_test (issue #26) ==\n");

    /* init_extraction() loads the protocol plugins and registers every tcpip
     * protocol, so the loaders can resolve protocol names via
     * get_protocol_id_by_name(). It must run from the install prefix so the
     * SDK's CWD-relative "plugins/" lookup resolves (see the runner script). */
    if (!init_extraction()) {
        fprintf(stderr, "init_extraction failed\n");
        return 2;
    }

    test_ip_ranges();
    test_port_map();

    close_extraction();

    printf("\n%d/%d checks passed\n", g_checks - g_failures, g_checks);
    if (g_failures) {
        printf("RESULT: FAIL (%d failure(s))\n", g_failures);
        return 1;
    }
    printf("RESULT: PASS\n");
    return 0;
}
