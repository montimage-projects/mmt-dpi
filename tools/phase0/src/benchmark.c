/**
 * MMT-DPI Benchmark Tool
 *
 * Measures classification/extraction throughput over an offline pcap using
 * the public libmmt_core API. Build against an installed SDK, e.g.:
 *
 *   gcc -o benchmark benchmark.c \
 *       -I /opt/mmt/dpi/include -L /opt/mmt/dpi/lib \
 *       -lmmt_core -ldl -lpcap
 *
 *   ./benchmark capture.pcap
 */
#include "mmt_core.h"
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static uint64_t total_packets = 0;
static uint64_t total_bytes = 0;

static int packet_processor(const ipacket_t *ipacket, void *args) {
    (void) ipacket;
    (void) args;
    total_packets++;
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <pcap_file>\n", argv[0]);
        return 1;
    }

    const char *pcap_file = argv[1];
    printf("=== MMT-DPI Benchmark ===\n");
    printf("File: %s\n", pcap_file);
    fflush(stdout);

    init_extraction();

    char errbuf[1024];
    mmt_handler_t *handler = mmt_init_handler(DLT_EN10MB, 0, errbuf);
    if (!handler) {
        fprintf(stderr, "Failed to create MMT handler: %s\n", errbuf);
        return 1;
    }

    register_extraction_attribute_by_name(handler, "META", "PACKET_LEN");
    register_extraction_attribute_by_name(handler, "META", "PROTOCOL_NAME");
    register_packet_handler(handler, 1, packet_processor, NULL);

    pcap_t *pcap = pcap_open_offline(pcap_file, errbuf);
    if (!pcap) {
        fprintf(stderr, "Failed to open pcap '%s': %s\n", pcap_file, errbuf);
        mmt_close_handler(handler);
        close_extraction();
        return 1;
    }

    struct timespec start_time, end_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);

    struct pkthdr header;
    struct pcap_pkthdr *p_pkthdr;
    const u_char *data;
    int ret;
    while ((ret = pcap_next_ex(pcap, &p_pkthdr, &data)) == 1) {
        header.ts = p_pkthdr->ts;
        header.caplen = p_pkthdr->caplen;
        header.len = p_pkthdr->len;
        total_bytes += p_pkthdr->len;
        packet_process(handler, &header, data);
    }

    clock_gettime(CLOCK_MONOTONIC, &end_time);
    pcap_close(pcap);

    double elapsed = (end_time.tv_sec - start_time.tv_sec) +
                     (end_time.tv_nsec - start_time.tv_nsec) / 1e9;
    double mbps = elapsed > 0 ? (total_bytes * 8.0) / elapsed / 1e6 : 0.0;
    double pps = elapsed > 0 ? total_packets / elapsed : 0.0;

    printf("\n=== Results ===\n");
    printf("Packets: %lu\n", (unsigned long)total_packets);
    printf("Bytes: %lu\n", (unsigned long)total_bytes);
    printf("Elapsed: %.4f s\n", elapsed);
    printf("Throughput: %.2f Mbps\n", mbps);
    printf("Packet rate: %.2f pps\n", pps);
    printf("----------------\n");

    mmt_close_handler(handler);
    close_extraction();
    return 0;
}
