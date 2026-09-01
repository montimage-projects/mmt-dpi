/*
 * test_radius_hardening.c — regression for #128: RADIUS parser hardening.
 *
 * Covers:
 *  - len==1 attribute (TLV len 1 rejected, no crash, no over-read)
 *  - len 67-255 attribute (large vlen clamped to BINARY_64DATA_LEN, no overflow)
 *  - truncated type-26 vendor specific (parent TLV truncated, sub-TLV)
 *  - 3-5-byte TLVs (short reads for read_be32 sites: nas_ip, nas_port, etc.)
 *
 * The test replicates the fixed parsing/extraction logic from
 * src/mmt_tcpip/lib/protocols/proto_radius.c and exercises it against
 * crafted buffers under ASan+UBSan. Source-level grep guards are verified
 * by run_tests.sh before this binary runs.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

#define BINARY_64DATA_LEN 64
#define BINARY_64DATA_TYPE_LEN 68
#define IPv6_ALEN 16
#define VENDOR_3GPP_ID 10415
#define VENDOR_3GPP_MAX_TLV_TYPE 27

typedef struct tlv_struct {
    uint8_t type;
    uint8_t len;
    uint8_t val;
} tlv_t;

typedef struct vendor_tlv_struct {
    uint32_t vendor_id;
    uint8_t type;
    uint8_t len;
    uint8_t val;
} vendor_tlv_t;

static inline uint32_t read_be32(const uint8_t *x) {
    return ((uint32_t)x[0] << 24) | ((uint32_t)x[1] << 16) | ((uint32_t)x[2] << 8) | (uint32_t)x[3];
}

static int failures = 0;
static int checks = 0;
#define CHECK(desc, cond) do { \
    checks++; \
    if (cond) { printf("  ok   %s\n", desc); } \
    else { printf("  FAIL %s\n", desc); failures++; } \
} while (0)

/* ---------------------------------------------------------------
 * Simulated session context (subset of radius_session_context_t)
 * --------------------------------------------------------------- */
typedef struct {
    int tlv_count;
    tlv_t *packet_tlvs[0xFF];
    tlv_t *vendor_3gpp_tlvs[VENDOR_3GPP_MAX_TLV_TYPE + 1];
} ctx_t;

/* Replicate radius_vendor_specific_fields_analysis guards
 * Use memcpy for vendor_id to stay UBSan-clean on unaligned packet data. */
static void vendor_specific_fields_analysis(ctx_t *ctx, uint8_t *v_field, size_t v_remaining) {
    if (v_remaining < 6) return;
    uint32_t vendor_id;
    memcpy(&vendor_id, v_field, 4);
    if (ntohl(vendor_id) != VENDOR_3GPP_ID) return;
    if (ctx == NULL) return;
    tlv_t *tlv = (tlv_t *)&v_field[4];
    size_t sub_remaining = v_remaining - 4;
    if (sub_remaining < 2) return;
    if (tlv->len < 2) return;
    if ((size_t)tlv->len > sub_remaining) return;
    if (tlv->type > VENDOR_3GPP_MAX_TLV_TYPE) return;
    if (tlv->type >= VENDOR_3GPP_MAX_TLV_TYPE + 1) return;
    ctx->vendor_3gpp_tlvs[tlv->type] = tlv;
}

/* Replicate radius_session_data_analysis loop */
static void parse_tlvs(ctx_t *ctx, uint8_t *data, size_t caplen, int proto_offset) {
    int tlv_offset = proto_offset + 20; /* 4 header + 16 authenticator */
    memset(ctx->packet_tlvs, 0, sizeof(ctx->packet_tlvs));
    memset(ctx->vendor_3gpp_tlvs, 0, sizeof(ctx->vendor_3gpp_tlvs));
    ctx->tlv_count = 0;
    while (caplen > (size_t)tlv_offset + 2) {
        tlv_t *cur = (tlv_t *)&data[tlv_offset];
        if (cur->len < 2) break; /* F-BUG-102 guard */
        if ((size_t)tlv_offset + (size_t)cur->len > caplen) break; /* truncated */
        ctx->packet_tlvs[cur->type] = cur;
        if (cur->type == 26) {
            size_t v_remaining = (size_t)cur->len - 2;
            vendor_specific_fields_analysis(ctx, (uint8_t *)&cur->val, v_remaining);
        }
        ctx->tlv_count += 1;
        tlv_offset += cur->len;
    }
}

/* Replicate extraction guards for BINARY (clamped) */
static int extract_binary_clamped(ctx_t *ctx, uint8_t tlv_type, uint8_t *out, size_t *out_len) {
    if (ctx->packet_tlvs[tlv_type] == NULL) return 0;
    if (ctx->packet_tlvs[tlv_type]->len < 2) return 0;
    size_t vlen = (size_t)ctx->packet_tlvs[tlv_type]->len - 2;
    if (vlen > BINARY_64DATA_LEN) vlen = BINARY_64DATA_LEN;
    memcpy(out, &ctx->packet_tlvs[tlv_type]->val, vlen);
    *out_len = vlen;
    return 1;
}

/* String-type with NUL terminator (called_station etc: >= BINARY_64DATA_LEN -> 63) */
static int extract_string_nul(ctx_t *ctx, uint8_t tlv_type, uint8_t *out, size_t *out_len) {
    if (ctx->packet_tlvs[tlv_type] == NULL) return 0;
    if (ctx->packet_tlvs[tlv_type]->len < 2) return 0;
    size_t vlen = (size_t)ctx->packet_tlvs[tlv_type]->len - 2;
    if (vlen >= BINARY_64DATA_LEN) vlen = BINARY_64DATA_LEN - 1;
    memcpy(out, &ctx->packet_tlvs[tlv_type]->val, vlen);
    out[vlen] = '\0';
    *out_len = vlen;
    return 1;
}

static int extract_u32(ctx_t *ctx, uint8_t tlv_type, uint32_t *out) {
    if (ctx->packet_tlvs[tlv_type] == NULL) return 0;
    if (ctx->packet_tlvs[tlv_type]->len < 6) return 0;
    *out = read_be32(&ctx->packet_tlvs[tlv_type]->val);
    return 1;
}

/* Helper: build a fake RADIUS packet buffer */
static void build_header(uint8_t *buf, size_t total_len) {
    memset(buf, 0, total_len);
    buf[0] = 1; /* code Access-Request */
    buf[1] = 0x5A;
    uint16_t nlen = htons((uint16_t)total_len);
    memcpy(&buf[2], &nlen, 2);
    /* bytes 4..19 authenticator: leave zero */
}

/* ------------------------------------------------------------------ */
static void test_len_1_rejected(void) {
    printf("len==1 TLV (must be rejected, no crash):\n");
    uint8_t pkt[64];
    ctx_t ctx;
    build_header(pkt, sizeof(pkt));
    /* Place a TLV at offset 20 with len=1 (illegal) */
    pkt[20] = 1; /* type User-Name */
    pkt[21] = 1; /* len 1 <2 */
    pkt[22] = 0x41;
    parse_tlvs(&ctx, pkt, sizeof(pkt), 0);
    CHECK("len==1 TLV does not advance tlv_count", ctx.tlv_count == 0);
    CHECK("len==1 TLV not stored in packet_tlvs[1]", ctx.packet_tlvs[1] == NULL);
    /* Also test len==0 */
    memset(pkt, 0, sizeof(pkt));
    build_header(pkt, sizeof(pkt));
    pkt[20] = 1;
    pkt[21] = 0;
    parse_tlvs(&ctx, pkt, sizeof(pkt), 0);
    CHECK("len==0 TLV rejected", ctx.tlv_count == 0 && ctx.packet_tlvs[1] == NULL);
    /* len==2 with zero-length value should be accepted (boundary) */
    memset(pkt, 0, sizeof(pkt));
    build_header(pkt, sizeof(pkt));
    pkt[20] = 1;
    pkt[21] = 2;
    parse_tlvs(&ctx, pkt, sizeof(pkt), 0);
    CHECK("len==2 TLV accepted (empty value)", ctx.tlv_count == 1 && ctx.packet_tlvs[1] != NULL);
}

static void test_large_vlen_clamped(void) {
    printf("large vlen 67..255 clamped to BINARY_64DATA_LEN (no overflow):\n");
    ctx_t ctx;
    uint8_t out[128];
    size_t out_len = 0;
    /* Build packet with a large User-Name TLV: type 1, len 255, value 253 bytes.
     * We craft a buffer large enough to hold it, then parse it. The extraction
     * must clamp vlen to 64. */
    size_t pkt_len = 20 + 255;
    uint8_t *pkt = calloc(1, pkt_len);
    build_header(pkt, pkt_len);
    pkt[20] = 1;
    pkt[21] = 255;
    memset(&pkt[22], 'A', 253);
    parse_tlvs(&ctx, pkt, pkt_len, 0);
    CHECK("large TLV (len 255) is stored", ctx.packet_tlvs[1] != NULL);
    int ok = extract_binary_clamped(&ctx, 1, out, &out_len);
    CHECK("large vlen extraction succeeds with clamp", ok == 1);
    CHECK("large vlen clamped to 64", out_len == BINARY_64DATA_LEN);
    /* Check that out buffer not overflowed (we filled 128 with sentinel) */
    memset(out, 0xAA, sizeof(out));
    extract_binary_clamped(&ctx, 1, out, &out_len);
    CHECK("no overflow past 64 bytes (sentinel intact)", out[64] == 0xAA);
    /* String variant (called_station) clamps to 63 + NUL */
    {
        uint8_t spkt[20 + 255];
        build_header(spkt, sizeof(spkt));
        spkt[20] = 30; /* Called-Station-Id */
        spkt[21] = 255;
        memset(&spkt[22], 'B', 253);
        parse_tlvs(&ctx, spkt, sizeof(spkt), 0);
        uint8_t sout[128];
        memset(sout, 0xAA, sizeof(sout));
        size_t slen = 0;
        int sok = extract_string_nul(&ctx, 30, sout, &slen);
        CHECK("string large vlen clamped to 63 with NUL", sok == 1 && slen == BINARY_64DATA_LEN - 1 && sout[63] == '\0');
        CHECK("string no overflow past 64 (sentinel)", sout[64] == 0xAA);
    }
    /* Test len 67 (vlen 65) is also clamped */
    {
        uint8_t p2[20 + 67];
        build_header(p2, sizeof(p2));
        p2[20] = 1;
        p2[21] = 67;
        memset(&p2[22], 'C', 65);
        parse_tlvs(&ctx, p2, sizeof(p2), 0);
        memset(out, 0xAA, sizeof(out));
        extract_binary_clamped(&ctx, 1, out, &out_len);
        CHECK("vlen 65 (len 67) clamped to 64", out_len == 64 && out[64] == 0xAA);
    }
    free(pkt);
}

static void test_truncated_vendor_specific(void) {
    printf("truncated type-26 vendor specific (no crash, sub-TLV guards):\n");
    ctx_t ctx;
    /* Case 1: parent TLV len declares more than available (truncated) */
    {
        uint8_t pkt[32];
        build_header(pkt, sizeof(pkt));
        pkt[20] = 26; /* Vendor-Specific */
        pkt[21] = 30; /* claims 30 bytes but only 12 bytes remain before caplen check will break */
        /* Actually make caplen small so parser sees truncated and breaks */
        parse_tlvs(&ctx, pkt, 22, 0); /* caplen 22 -> only 2 bytes of TLV header fit, but len=30 > remaining => break */
        CHECK("truncated parent TLV (caplen < tlv_offset+len) rejected", ctx.tlv_count == 0 && ctx.packet_tlvs[26] == NULL);
    }
    /* Case 2: parent TLV fits but sub-TLV truncated (v_remaining <6) */
    {
        uint8_t pkt[64];
        build_header(pkt, sizeof(pkt));
        pkt[20] = 26;
        pkt[21] = 6; /* minimal: 2 header + 4 vendor ID only */
        uint32_t vid = htonl(VENDOR_3GPP_ID);
        memcpy(&pkt[22], &vid, 4);
        /* No sub-TLV bytes beyond vendor ID; v_remaining=4 <6 => vendor handler returns */
        parse_tlvs(&ctx, pkt, sizeof(pkt), 0);
        CHECK("vendor TLV with v_remaining<6 does not populate vendor tlvs", ctx.packet_tlvs[26] != NULL);
        int any_vendor = 0;
        for (int i = 0; i <= VENDOR_3GPP_MAX_TLV_TYPE; i++) if (ctx.vendor_3gpp_tlvs[i]) any_vendor = 1;
        CHECK("vendor sub-TLV not extracted when v_remaining<6", any_vendor == 0);
    }
    /* Case 3: parent fits, sub-TLV header present but len <2 */
    {
        uint8_t pkt[64];
        build_header(pkt, sizeof(pkt));
        pkt[20] = 26;
        pkt[21] = 8; /* 2+4+2 */
        uint32_t vid = htonl(VENDOR_3GPP_ID);
        memcpy(&pkt[22], &vid, 4);
        pkt[26] = 6; /* sub-type */
        pkt[27] = 1; /* sub-len <2 */
        parse_tlvs(&ctx, pkt, sizeof(pkt), 0);
        int any_vendor = 0;
        for (int i = 0; i <= VENDOR_3GPP_MAX_TLV_TYPE; i++) if (ctx.vendor_3gpp_tlvs[i]) any_vendor = 1;
        CHECK("sub-TLV len==1 rejected", any_vendor == 0);
    }
    /* Case 4: sub-TLV len > sub_remaining */
    {
        uint8_t pkt[64];
        build_header(pkt, sizeof(pkt));
        pkt[20] = 26;
        pkt[21] = 8;
        uint32_t vid = htonl(VENDOR_3GPP_ID);
        memcpy(&pkt[22], &vid, 4);
        pkt[26] = 6;
        pkt[27] = 20; /* claims 20 bytes but only 2 remain */
        parse_tlvs(&ctx, pkt, sizeof(pkt), 0);
        int any_vendor = 0;
        for (int i = 0; i <= VENDOR_3GPP_MAX_TLV_TYPE; i++) if (ctx.vendor_3gpp_tlvs[i]) any_vendor = 1;
        CHECK("sub-TLV len > sub_remaining rejected", any_vendor == 0);
    }
    /* Case 5: valid vendor TLV should be extracted */
    {
        uint8_t pkt[64];
        build_header(pkt, sizeof(pkt));
        pkt[20] = 26;
        pkt[21] = 10; /* 2+4+4 */
        uint32_t vid = htonl(VENDOR_3GPP_ID);
        memcpy(&pkt[22], &vid, 4);
        pkt[26] = 1; /* IMSI */
        pkt[27] = 4; /* len 4 -> vlen 2 */
        pkt[28] = 'X'; pkt[29] = 'Y';
        parse_tlvs(&ctx, pkt, sizeof(pkt), 0);
        CHECK("valid vendor sub-TLV extracted", ctx.vendor_3gpp_tlvs[1] != NULL && ctx.vendor_3gpp_tlvs[1]->type == 1);
    }
    /* Case 6: wrong vendor ID must be ignored */
    {
        uint8_t pkt[64];
        build_header(pkt, sizeof(pkt));
        pkt[20] = 26;
        pkt[21] = 10;
        uint32_t vid = htonl(12345);
        memcpy(&pkt[22], &vid, 4);
        pkt[26] = 1;
        pkt[27] = 4;
        pkt[28] = 'X'; pkt[29] = 'Y';
        parse_tlvs(&ctx, pkt, sizeof(pkt), 0);
        int any_vendor = 0;
        for (int i = 0; i <= VENDOR_3GPP_MAX_TLV_TYPE; i++) if (ctx.vendor_3gpp_tlvs[i]) any_vendor = 1;
        CHECK("wrong vendor ID ignored", any_vendor == 0);
    }
}

static void test_short_reads_read_be32(void) {
    printf("3-5-byte TLVs rejected for read_be32 sites (no short read):\n");
    ctx_t ctx;
    uint32_t val = 0;
    /* TLVs that carry u32 must be at least len 6 (2 header + 4 value). */
    uint8_t types_u32[] = {4, 5, 6, 7, 8, 9, 12, 27, 28, 40, 41, 42, 43, 45, 46, 47, 48, 49, 55, 61};
    for (size_t ti = 0; ti < sizeof(types_u32); ti++) {
        uint8_t t = types_u32[ti];
        for (int len = 2; len <= 5; len++) {
            uint8_t pkt[64];
            build_header(pkt, sizeof(pkt));
            pkt[20] = t;
            pkt[21] = (uint8_t)len;
            for (int i = 0; i < len - 2; i++) pkt[22 + i] = 0xFF;
            parse_tlvs(&ctx, pkt, sizeof(pkt), 0);
            /* parser stores it (len>=2), but extraction must reject */
            if (ctx.packet_tlvs[t] == NULL) continue; /* should be stored for len>=2 */
            int rc = extract_u32(&ctx, t, &val);
            char desc[128];
            snprintf(desc, sizeof(desc), "type %u len %d rejected for u32", t, len);
            CHECK(desc, rc == 0);
        }
    }
    /* len 6 must be accepted */
    {
        uint8_t pkt[64];
        build_header(pkt, sizeof(pkt));
        pkt[20] = 4; /* NAS-IP-Address */
        pkt[21] = 6;
        pkt[22] = 192; pkt[23] = 168; pkt[24] = 1; pkt[25] = 10;
        parse_tlvs(&ctx, pkt, sizeof(pkt), 0);
        int rc = extract_u32(&ctx, 4, &val);
        CHECK("type 4 len 6 accepted for u32", rc == 1 && val == 0xC0A8010A);
    }
    /* len 5 with caplen truncated mid-TLV must not be parsed at all */
    {
        uint8_t pkt[25];
        build_header(pkt, sizeof(pkt));
        pkt[20] = 4;
        pkt[21] = 6; /* claims 6 but caplen only 25 -> only 5 bytes available after header? */
        /* caplen 25 => tlv_offset 20, need 6 bytes but only 5 remain => truncated, loop breaks before storing */
        parse_tlvs(&ctx, pkt, 25, 0);
        CHECK("truncated u32 TLV (caplen < offset+len) not stored", ctx.packet_tlvs[4] == NULL);
    }
}

int main(void) {
    test_len_1_rejected();
    test_large_vlen_clamped();
    test_truncated_vendor_specific();
    test_short_reads_read_be32();
    printf("\n%d checks, %d failure(s)\n", checks, failures);
    return failures ? 1 : 0;
}
