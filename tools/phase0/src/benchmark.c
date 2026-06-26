/**
 * MMT-DPI Benchmark Tool
 * Uses the installed libmmt_core.so API correctly
 */
#include "mmt_core.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static uint64_t total_packets = 0;
static uint64_t total_bytes = 0;
static struct timespec start_time, end_time;

static void packet_processor(const ipacket_t *ipacket, void *args) {
    total_packets++;
    total_bytes += ipacket->m_packet_len;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <pcap_file>\n", argv[0]);
        return 1;
    }

    char *pcap_file = argv[1];
    printf("=== MMT-DPI Benchmark ===\n");
    printf("File: %s\n", pcap_file);
    fflush(stdout);

    init_extraction();

    /* The installed library's API:  mmt_handler_t *mmt_init_handler(mmt_handler_t*, int, int, char*)
       But the header says:         int mmt_init_handler(mmt_handler_t*, int, int, char*)
       Actual return type is pointer. We cast to match. */
    mmt_handler_t *handler = (mmt_handler_t*)mmt_init_handler(NULL, DLT_EN10MB, 0, NULL);
    if (!handler) {
        fprintf(stderr, "Failed to create MMT handler\n");
        return 1;
    }

    register_extraction_attribute_by_name(handler, "META", "PACKET_LEN");
    register_extraction_attribute_by_name(handler, "META", "PROTOCOL_NAME");
    register_packet_handler(handler, 1, packet_processor, NULL);

    sprintf(handler->bpf, "");

    clock_gettime(CLOCK_MONOTONIC, &start_time);

    int ret = mmt_process_pcap(handler, pcap_file);

    clock_gettime(CLOCK_MONOTONIC, &end_time);

    double elapsed = (end_time.tv_sec - start_time.tv_sec) +
                     (end_time.tv_nsec - start_time.tv_nsec) / 1e9;
    double mbps = (total_bytes * 8.0) / elapsed / 1e6;
    double pps = total_packets / elapsed;

    printf("\n=== Results ===\n");
    printf("Packets: %lu\n", (unsigned long)total_packets);
    printf("Bytes: %lu\n", (unsigned long)total_bytes);
    printf("Elapsed: %.4f s\n", elapsed);
    printf("Throughput: %.2f Mbps\n", mbps);
    printf("Packet rate: %.2f pps\n", pps);
    printf("----------------\n");

    mmt_close_handler(handler);
    return 0;
}
