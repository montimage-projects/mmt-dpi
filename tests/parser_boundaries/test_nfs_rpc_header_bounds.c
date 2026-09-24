/*
 * test_nfs_rpc_header_bounds.c — crafted-fixture test for issue #407:
 * the NFS attribute extractors (src/mmt_tcpip/lib/protocols/proto_nfs.c)
 * read big-endian u32 fields of the ONC-RPC call header at fixed offsets
 * from the NFS payload start (which begins with the 4-byte TCP record mark):
 *
 *   +0 record mark | +4 xid | +8 msg_type | +12 rpc_version | +16 program
 *   +20 prog_version | +24 procedure
 *
 * Before the fix the message-type read at +8 was guarded only by
 * "+8 < caplen" and the field reads at +12/+16 were unchecked (+20/+24 were
 * guarded by "< caplen"), so a truncated capture let the extractor read up
 * to 4 bytes past the captured buffer and report a value built from them.
 * Every read must now be bounded by mmt_have_bytes(): a field that is not
 * fully captured yields "not extracted" (0), a complete one still extracts.
 *
 * The capture buffer is heap-allocated at exactly caplen bytes so ASan
 * (SANITIZE=asan) brackets it; without a sanitizer the return values alone
 * fail red on the unfixed code.
 *
 * The test links the built SDK and calls the exported extractors directly
 * (same convention as test_dtls_wire_extent_unit.c).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "mmt_core.h"
#include "packet_processing.h"          /* ipacket wiring, attribute_t */
#include "mmt_tcpip_plugin_structs.h"   /* mmt_tcpip_internal_packet_t */

/* Exported non-static but absent from the installed headers. */
typedef int (*nfs_extractor_t)(const ipacket_t *, unsigned, attribute_t *);
int nfs_rpc_version_extraction(const ipacket_t *, unsigned, attribute_t *);
int nfs_program_extraction(const ipacket_t *, unsigned, attribute_t *);
int nfs_prog_version_extraction(const ipacket_t *, unsigned, attribute_t *);
int nfs_procedure_extraction(const ipacket_t *, unsigned, attribute_t *);
int nfs_tag_extraction(const ipacket_t *, unsigned, attribute_t *);
int nfs_minorversion_extraction(const ipacket_t *, unsigned, attribute_t *);
int nfs_nb_operations_extraction(const ipacket_t *, unsigned, attribute_t *);
int nfs_file_opcode_extraction(const ipacket_t *, unsigned, attribute_t *);
int nfs_file_name_extraction(const ipacket_t *, unsigned, attribute_t *);
int nfs_file_new_name_extraction(const ipacket_t *, unsigned, attribute_t *);

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond, ...) do {                                        \
        g_checks++;                                                  \
        if (!(cond)) {                                               \
            printf("  FAIL: ");                                      \
            printf(__VA_ARGS__);                                     \
            printf("\n");                                            \
            g_failures++;                                            \
        }                                                            \
    } while (0)

/* NFS payload offset inside the capture (Ethernet + IPv4 + TCP headers). */
#define NFS_OFF 54u

typedef struct {
    ipacket_t pkt;
    proto_hierarchy_t offsets;
    proto_hierarchy_t hier;
    pkthdr_t hdr;
    mmt_tcpip_internal_packet_t ipkt;
    u_char *buf;
} fixture_t;

/* RPC call header, all fields present: record mark, xid, msg_type = 0
 * (CALL), rpcvers 2, program 100003 (NFS), version 4, procedure 1. */
static const uint8_t rpc_call[] = {
    0x80, 0x00, 0x00, 0x74,   /* +0  record mark (last fragment) */
    0x12, 0x34, 0x56, 0x78,   /* +4  xid */
    0x00, 0x00, 0x00, 0x00,   /* +8  msg_type CALL */
    0x00, 0x00, 0x00, 0x02,   /* +12 rpc version */
    0x00, 0x01, 0x86, 0xa3,   /* +16 program */
    0x00, 0x00, 0x00, 0x04,   /* +20 program version */
    0x00, 0x00, 0x00, 0x01,   /* +24 procedure */
};

/* caplen = NFS_OFF + nfs_bytes; the buffer holds exactly caplen bytes. */
static void fixture_init(fixture_t *f, unsigned nfs_bytes, uint32_t msg_type) {
    unsigned caplen = NFS_OFF + nfs_bytes;
    memset(f, 0, sizeof(*f));
    f->buf = (u_char *)malloc(caplen);
    if (!f->buf) { perror("malloc"); exit(2); }
    memset(f->buf, 0, caplen);
    uint8_t hdr[sizeof(rpc_call)];
    memcpy(hdr, rpc_call, sizeof(hdr));
    hdr[8] = (uint8_t)(msg_type >> 24); hdr[9] = (uint8_t)(msg_type >> 16);
    hdr[10] = (uint8_t)(msg_type >> 8); hdr[11] = (uint8_t)msg_type;
    memcpy(f->buf + NFS_OFF, hdr,
           nfs_bytes < sizeof(hdr) ? nfs_bytes : sizeof(hdr));
    f->offsets.proto_path[0] = NFS_OFF;
    f->offsets.len = 1;
    f->hier.len = 1;
    f->hdr.caplen = caplen;
    f->hdr.len = caplen;
    f->ipkt.payload_packet_len = (uint16_t)(nfs_bytes ? nfs_bytes : 1);
    f->pkt.p_hdr = &f->hdr;
    f->pkt.data = f->buf;
    f->pkt.proto_headers_offset = &f->offsets;
    f->pkt.proto_hierarchy = &f->hier;
    f->pkt.internal_cumulative_offset_valid = 0;
    f->pkt.internal_packet = &f->ipkt;
}

static int run(nfs_extractor_t fn, unsigned nfs_bytes, uint32_t msg_type,
               uint32_t *out) {
    fixture_t f;
    uint32_t value = 0xDEADBEEFu;
    uint8_t scratch[64];
    attribute_t attr;
    memset(&attr, 0, sizeof(attr));
    memset(scratch, 0, sizeof(scratch));
    attr.data = (fn == nfs_rpc_version_extraction
                 || fn == nfs_program_extraction
                 || fn == nfs_prog_version_extraction
                 || fn == nfs_procedure_extraction) ? (void *)&value
                                                    : (void *)scratch;
    fixture_init(&f, nfs_bytes, msg_type);
    int rc = fn(&f.pkt, 0, &attr);
    free(f.buf);
    if (out) *out = value;
    return rc;
}

static void check_fixed_field(const char *name, nfs_extractor_t fn,
                              unsigned field_off, uint32_t expected) {
    uint32_t v = 0;
    unsigned need = field_off + 4;

    /* Complete field: extracted with the right value. */
    CHECK(run(fn, need, 0, &v) == 1 && v == expected,
          "%s: %u captured bytes must extract %u (got %u)",
          name, need, expected, v);
    CHECK(run(fn, sizeof(rpc_call), 0, &v) == 1 && v == expected,
          "%s: full header must extract %u", name, expected);

    /* Field truncated by 1..4 bytes: never extracted (was an over-read). */
    for (unsigned n = field_off; n < need; n++)
        CHECK(run(fn, n, 0, NULL) == 0,
              "%s: %u captured bytes (field at +%u truncated) must not extract",
              name, n, field_off);

    /* Reply message: not a call header, not extracted. */
    CHECK(run(fn, sizeof(rpc_call), 1, NULL) == 0,
          "%s: RPC reply must not extract", name);
}

int main(void) {
    printf("NFS RPC header bounds (issue #407)\n");

    check_fixed_field("rpc_version", nfs_rpc_version_extraction, 12, 2);
    check_fixed_field("program", nfs_program_extraction, 16, 100003);
    check_fixed_field("prog_version", nfs_prog_version_extraction, 20, 4);
    check_fixed_field("procedure", nfs_procedure_extraction, 24, 1);

    /* The shared prologue: msg_type at +8 needs 12 captured bytes, and the
     * leading record-mark byte needs at least one. Every RPC-header
     * extractor must refuse a capture that ends inside msg_type. */
    static const struct { const char *name; nfs_extractor_t fn; } all[] = {
        { "rpc_version", nfs_rpc_version_extraction },
        { "program", nfs_program_extraction },
        { "prog_version", nfs_prog_version_extraction },
        { "procedure", nfs_procedure_extraction },
        { "tag", nfs_tag_extraction },
        { "minorversion", nfs_minorversion_extraction },
        { "nb_operations", nfs_nb_operations_extraction },
        { "file_opcode", nfs_file_opcode_extraction },
        { "file_name", nfs_file_name_extraction },
        { "file_new_name", nfs_file_new_name_extraction },
    };
    for (size_t i = 0; i < sizeof(all) / sizeof(all[0]); i++)
        for (unsigned n = 0; n < 12; n++)
            CHECK(run(all[i].fn, n, 0, NULL) == 0,
                  "%s: %u captured NFS bytes (msg_type truncated) must not extract",
                  all[i].name, n);

    printf("  %d/%d checks passed\n", g_checks - g_failures, g_checks);
    return g_failures ? 1 : 0;
}
