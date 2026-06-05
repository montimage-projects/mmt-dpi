/**
 * phase0_classify — deterministic protocol-classification fingerprint tool.
 *
 * Part of the MMT-DPI Master Improvement Plan, Phase 0 (baseline harness).
 * See tools/phase0/README.md.
 *
 * For a given pcap it processes every packet and, for each packet, builds the
 * classified protocol path (e.g. "META.ETHERNET.IP.TCP.HTTP") from the packet's
 * proto_hierarchy. It then prints, sorted, one line per distinct path:
 *
 *     <count><TAB><path>
 *
 * The output is intentionally free of timestamps, addresses, packet ordering
 * and any other volatile data, so it is a stable fingerprint of the SDK's
 * classification decisions. Capture it once on Phase-0 `main` (the golden
 * baseline) and diff against it after every later phase — any diff is a
 * classification regression to investigate.
 *
 * Build (done by capture_baseline.sh against an installed prefix):
 *   gcc -O2 -o phase0_classify phase0_classify.c \
 *       -I <prefix>/dpi/include -L <prefix>/dpi/lib -lmmt_core -ldl -lpcap
 *
 * Usage:
 *   phase0_classify <file.pcap>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>

#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"

#define MAX_PATH_STR   512
#define MAX_DISTINCT   4096

typedef struct {
    char path[MAX_PATH_STR];
    unsigned long count;
} path_entry_t;

static path_entry_t g_paths[MAX_DISTINCT];
static int          g_npaths = 0;

/* Record one observed protocol path, aggregating identical paths. */
static void record_path(const char *path) {
    int i;
    for (i = 0; i < g_npaths; i++) {
        if (strcmp(g_paths[i].path, path) == 0) {
            g_paths[i].count++;
            return;
        }
    }
    if (g_npaths >= MAX_DISTINCT) {
        /* Should never happen for the golden set; flag loudly if it does. */
        fprintf(stderr, "phase0_classify: distinct-path table full (%d)\n",
                MAX_DISTINCT);
        return;
    }
    snprintf(g_paths[g_npaths].path, MAX_PATH_STR, "%s", path);
    g_paths[g_npaths].count = 1;
    g_npaths++;
}

static int packet_handler(const ipacket_t *ipacket, void *user_args) {
    char path[MAX_PATH_STR];
    int  len = 0;
    int  i;
    const proto_hierarchy_t *ph = ipacket->proto_hierarchy;

    if (ph == NULL || ph->len <= 0) {
        record_path("<none>");
        return 0;
    }
    path[0] = '\0';
    for (i = 0; i < ph->len && i < PROTO_PATH_SIZE; i++) {
        const char *name = get_protocol_name_by_id(ph->proto_path[i]);
        int n;
        if (name == NULL) name = "?";
        n = snprintf(path + len, sizeof(path) - len,
                     (i == 0) ? "%s" : ".%s", name);
        if (n < 0 || n >= (int)(sizeof(path) - len)) {
            len = sizeof(path) - 1;
            break;
        }
        len += n;
    }
    record_path(path);
    return 0;
}

/* qsort comparator: sort by path string for stable, order-independent output. */
static int cmp_path(const void *a, const void *b) {
    const path_entry_t *pa = (const path_entry_t *)a;
    const path_entry_t *pb = (const path_entry_t *)b;
    return strcmp(pa->path, pb->path);
}

int main(int argc, char **argv) {
    char            mmt_errbuf[1024];
    char            pcap_errbuf[PCAP_ERRBUF_SIZE];
    mmt_handler_t  *mmt_handler;
    pcap_t         *pcap;
    const u_char   *data;
    struct pcap_pkthdr  p_pkthdr;
    struct pkthdr   header;
    int             datalink;
    int             i;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <file.pcap>\n", argv[0]);
        return EXIT_FAILURE;
    }

    pcap = pcap_open_offline(argv[1], pcap_errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_offline(%s) failed: %s\n", argv[1], pcap_errbuf);
        return EXIT_FAILURE;
    }
    datalink = pcap_datalink(pcap);

    init_extraction();
    mmt_handler = mmt_init_handler(datalink, 0, mmt_errbuf);
    if (mmt_handler == NULL) {
        fprintf(stderr, "mmt_init_handler failed: %s\n", mmt_errbuf);
        pcap_close(pcap);
        close_extraction();
        return EXIT_FAILURE;
    }

    register_packet_handler(mmt_handler, 1, packet_handler, NULL);

    memset(&header, 0, sizeof(header));
    while ((data = pcap_next(pcap, &p_pkthdr)) != NULL) {
        header.ts     = p_pkthdr.ts;
        header.caplen = p_pkthdr.caplen;
        header.len    = p_pkthdr.len;
        packet_process(mmt_handler, &header, data);
    }

    qsort(g_paths, g_npaths, sizeof(g_paths[0]), cmp_path);
    for (i = 0; i < g_npaths; i++) {
        printf("%lu\t%s\n", g_paths[i].count, g_paths[i].path);
    }

    mmt_close_handler(mmt_handler);
    close_extraction();
    pcap_close(pcap);
    return EXIT_SUCCESS;
}
