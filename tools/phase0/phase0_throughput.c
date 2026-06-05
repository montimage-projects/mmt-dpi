/**
 * phase0_throughput — packet-processing throughput baseline (packets/second).
 *
 * Part of the MMT-DPI Master Improvement Plan, Phase 0 (baseline harness).
 * See tools/phase0/README.md.
 *
 * Loads an entire pcap into memory once, then replays it through the SDK
 * `iterations` times, measuring wall-clock time with CLOCK_MONOTONIC.
 * Replaying from memory removes pcap/disk I/O from the measured loop, so the
 * reported pps reflects the SDK hot path. Capture this on Phase-0 `main` and
 * compare after Phase 4 (build/LTO) and Phase 5 (hot-path performance).
 *
 * A *fresh* mmt_handler is created for each iteration, but only the inner
 * packet-processing loop is timed: the per-iteration mmt_init_handler /
 * mmt_close_handler calls are excluded from the measured window, so the
 * reported pps reflects the SDK hot path rather than handler setup/teardown
 * (the expensive one-time cost is init_extraction(), also outside the window).
 * A fresh handler per pass matters: replaying the identical packets through one
 * persistent handler drives stateful parsers and the TCP reassembly/session
 * tables into states the SDK never sees in real capture (same 5-tuple, same
 * sequence numbers, forever) and can crash. A fresh handler per pass keeps each
 * replay a clean, representative single-trace run.
 *
 * Build (done by capture_baseline.sh against an installed prefix):
 *   gcc -O2 -o phase0_throughput phase0_throughput.c \
 *       -I <prefix>/dpi/include -L <prefix>/dpi/lib -lmmt_core -ldl -lpcap
 *
 * Usage:
 *   phase0_throughput <file.pcap> [iterations]   (default iterations: 200)
 *
 * Output (one line, tab-separated, stable/diffable):
 *   <packets>\t<iterations>\t<elapsed_s>\t<pps>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pcap.h>

#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"

typedef struct {
    struct pkthdr header;
    unsigned char *data;
} stored_pkt_t;

int main(int argc, char **argv) {
    char            mmt_errbuf[1024];
    char            pcap_errbuf[PCAP_ERRBUF_SIZE];
    mmt_handler_t  *mmt_handler;
    pcap_t         *pcap;
    const u_char   *data;
    struct pcap_pkthdr  p_pkthdr;
    int             datalink;
    long            iterations = 200;
    long            it, i;
    size_t          cap = 4096, n = 0;
    stored_pkt_t   *pkts;
    struct timespec t0, t1;
    double          elapsed, pps;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <file.pcap> [iterations]\n", argv[0]);
        return EXIT_FAILURE;
    }
    if (argc >= 3) {
        iterations = strtol(argv[2], NULL, 10);
        if (iterations <= 0) iterations = 200;
    }

    pcap = pcap_open_offline(argv[1], pcap_errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_offline(%s) failed: %s\n", argv[1], pcap_errbuf);
        return EXIT_FAILURE;
    }
    datalink = pcap_datalink(pcap);

    /* Slurp the whole trace into memory. */
    pkts = (stored_pkt_t *)malloc(cap * sizeof(*pkts));
    if (pkts == NULL) { fprintf(stderr, "OOM\n"); pcap_close(pcap); return EXIT_FAILURE; }
    while ((data = pcap_next(pcap, &p_pkthdr)) != NULL) {
        if (n == cap) {
            cap *= 2;
            stored_pkt_t *tmp = (stored_pkt_t *)realloc(pkts, cap * sizeof(*pkts));
            if (tmp == NULL) { fprintf(stderr, "OOM\n"); free(pkts); pcap_close(pcap); return EXIT_FAILURE; }
            pkts = tmp;
        }
        memset(&pkts[n].header, 0, sizeof(pkts[n].header));
        pkts[n].header.ts     = p_pkthdr.ts;
        pkts[n].header.caplen = p_pkthdr.caplen;
        pkts[n].header.len    = p_pkthdr.len;
        /* malloc(0) is implementation-defined (may return NULL); use >=1. */
        pkts[n].data = (unsigned char *)malloc(p_pkthdr.caplen ? p_pkthdr.caplen : 1);
        if (pkts[n].data == NULL) { fprintf(stderr, "OOM\n"); free(pkts); pcap_close(pcap); return EXIT_FAILURE; }
        memcpy(pkts[n].data, data, p_pkthdr.caplen);
        n++;
    }
    pcap_close(pcap);

    if (n == 0) {
        fprintf(stderr, "%s: no packets\n", argv[1]);
        free(pkts);
        return EXIT_FAILURE;
    }

    init_extraction();
    /* Probe once so an unsupported link-type fails cleanly before timing. */
    mmt_handler = mmt_init_handler(datalink, 0, mmt_errbuf);
    if (mmt_handler == NULL) {
        fprintf(stderr, "mmt_init_handler failed: %s\n", mmt_errbuf);
        free(pkts);
        close_extraction();
        return EXIT_FAILURE;
    }
    mmt_close_handler(mmt_handler);

    /* Time only the packet-processing inner loop, accumulated across all
     * iterations. The per-iteration handler init/close stays (a fresh handler
     * per pass — see file header) but is kept out of the measured window. */
    elapsed = 0.0;
    for (it = 0; it < iterations; it++) {
        mmt_handler = mmt_init_handler(datalink, 0, mmt_errbuf);
        if (mmt_handler == NULL) break;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (i = 0; i < (long)n; i++) {
            packet_process(mmt_handler, &pkts[i].header, pkts[i].data);
        }
        clock_gettime(CLOCK_MONOTONIC, &t1);
        elapsed += (double)(t1.tv_sec - t0.tv_sec)
                 + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
        mmt_close_handler(mmt_handler);
    }
    mmt_handler = NULL;
    pps = (elapsed > 0.0) ? ((double)n * (double)iterations / elapsed) : 0.0;

    printf("%zu\t%ld\t%.4f\t%.0f\n", n, iterations, elapsed, pps);

    close_extraction();
    for (i = 0; i < (long)n; i++) free(pkts[i].data);
    free(pkts);
    return EXIT_SUCCESS;
}
