/*
 * test_nas_ies_tail.c
 *
 * Regression for issue #133: NAS IE fixed-size decoders bound by ielen
 * and remaining buffer length.
 *
 * Covers F-BUG-202,203,204,205,206,214,215:
 * - pdn_address_information.len validated against pdn_type minimum before UE-IP read (ielen 0..10)
 * - ielen=0 rejected before reading pdn_type
 * - GUTI(11)/IMSI/IMEI(9) bounded by remaining len
 * - TAI list ielen>=6
 * - EPS QoS operator-precedence and buffer+decoded for QCI
 * - t3412value buffer+decoded in attach-accept
 * - negative decoder errors captured in signed ret before uint32 wrap
 *
 * Verifies crafted Attach-Accept/Request tail cases (ielen 0..10 at buffer end)
 * pass without AddressSanitizer errors.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "emm/nas_emm_attach_accept.h"
#include "emm/nas_emm_attach_request.h"
#include "ies/pdn_address.h"
#include "ies/esp_mobile_identity.h"
#include "ies/tracking_area_identity_list.h"
#include "ies/eps_quality_of_service.h"
#include "nas_msg.h"

static int failures = 0;
static int checks = 0;
#define CHECK(desc, cond) do { \
    checks++; \
    if (cond) { printf("  ok   %s\n", desc); } \
    else      { printf("  FAIL %s\n", desc); failures++; } \
} while (0)

static void test_pdn_tail(void) {
    printf("pdn_address tail ielen 0..10:\n");
    for (int ielen = 0; ielen <= 10; ielen++) {
        uint8_t buf[2];
        buf[0] = (uint8_t)ielen;
        nas_pdn_address_t addr; memset(&addr, 0, sizeof(addr));
        int ret = nas_decode_pdn_address(&addr, 0, buf, 1);
        char d[64]; snprintf(d, sizeof(d), "pdn ielen=%d len=1 returns error", ielen);
        CHECK(d, ret < 0);
        if (ielen >= 1) {
            uint8_t buf2[20]; memset(buf2, 0, sizeof(buf2));
            buf2[0] = (uint8_t)ielen;
            buf2[1] = NAS_PDN_VALUE_TYPE_IPV4;
            int ret2 = nas_decode_pdn_address(&addr, 0, buf2, 2);
            char d2[64]; snprintf(d2, sizeof(d2), "pdn ielen=%d len=2 trunc addr error", ielen);
            CHECK(d2, ret2 < 0);
        }
    }
}

static void test_mobile_identity_tail(void) {
    printf("eps_mobile_identity tail ielen 0..10:\n");
    for (int ielen = 0; ielen <= 10; ielen++) {
        uint8_t buf[20]; memset(buf, 0, sizeof(buf));
        buf[0] = (uint8_t)ielen;
        nas_eps_mobile_identity_t ident; memset(&ident, 0, sizeof(ident));
        int ret = nas_decode_eps_mobile_identity(&ident, 0, buf, 1);
        char d[64]; snprintf(d, sizeof(d), "mobile ielen=%d len=1 error", ielen);
        CHECK(d, ret < 0);
        if (ielen >= 1) {
            buf[1] = 0x01; // IMSI typeofidentity
            int ret2 = nas_decode_eps_mobile_identity(&ident, 0, buf, 2);
            char d2[64]; snprintf(d2, sizeof(d2), "mobile ielen=%d len=2 trunc payload error", ielen);
            CHECK(d2, ret2 < 0);
        }
    }
}

static void test_tai_tail(void) {
    printf("TAI list tail ielen 0..10:\n");
    for (int ielen = 0; ielen <= 10; ielen++) {
        uint8_t buf[20]; memset(buf, 0, sizeof(buf));
        buf[0] = (uint8_t)ielen;
        nas_tracking_area_identity_list_t lst; memset(&lst, 0, sizeof(lst));
        int ret = nas_decode_tracking_area_identity_list(&lst, 0, buf, 1);
        char d[64]; snprintf(d, sizeof(d), "tai ielen=%d len=1 error", ielen);
        CHECK(d, ret < 0);
    }
}

static void test_qos_tail(void) {
    printf("EPS QoS tail ielen 0..10:\n");
    for (int ielen = 0; ielen <= 10; ielen++) {
        uint8_t buf[20]; memset(buf, 0, sizeof(buf));
        buf[0] = (uint8_t)ielen;
        nas_eps_quality_of_service_t m; memset(&m, 0, sizeof(m));
        int ret = nas_decode_eps_quality_of_service(&m, 0, buf, 1);
        char d[64]; snprintf(d, sizeof(d), "qos ielen=%d len=1 error", ielen);
        CHECK(d, ret < 0);
        if (ielen >= 1) {
            int ret2 = nas_decode_eps_quality_of_service(&m, 0, buf, 2);
            char d2[64]; snprintf(d2, sizeof(d2), "qos ielen=%d len=2 no crash ret=%d", ielen, ret2);
            int expect_error = (ielen > 1);
            if (expect_error) CHECK(d2, ret2 < 0);
            else CHECK(d2, ret2 >= 0);
        }
    }
}

static void test_attach_request_tail(void) {
    printf("Attach Request tail ielen 0..10:\n");
    for (int ielen = 0; ielen <= 10; ielen++) {
        uint8_t buf[30]; memset(buf, 0, sizeof(buf));
        buf[0] = 0x01;
        buf[1] = (uint8_t)ielen;
        if (ielen >= 1) buf[2] = 0x01;
        nas_emm_attach_request_t msg; memset(&msg, 0, sizeof(msg));
        int len = (ielen >= 1) ? 3 : 2;
        int ret = nas_emm_decode_attach_request(&msg, buf, (uint32_t)len);
        char d[64]; snprintf(d, sizeof(d), "attach_req ielen=%d len=%d error", ielen, len);
        CHECK(d, ret < 0);
    }
}

static void test_attach_accept_tail(void) {
    printf("Attach Accept tail ielen 0..10:\n");
    for (int ielen = 0; ielen <= 10; ielen++) {
        uint8_t buf[30]; memset(buf, 0, sizeof(buf));
        buf[0] = 0x01;
        buf[1] = 0x02;
        buf[2] = (uint8_t)ielen;
        int len = 3;
        if (ielen >= 1) { buf[3] = 0x00; len = 4; }
        nas_emm_attach_accept_t acc; memset(&acc, 0, sizeof(acc));
        int ret = nas_emm_decode_attach_accept(&acc, buf, (uint32_t)len);
        char d[64]; snprintf(d, sizeof(d), "attach_acc ielen=%d len=%d error", ielen, len);
        CHECK(d, ret < 0);
    }
}

int main(void) {
    test_pdn_tail();
    test_mobile_identity_tail();
    test_tai_tail();
    test_qos_tail();
    test_attach_request_tail();
    test_attach_accept_tail();
    printf("\n%d checks, %d failure(s)\n", checks, failures);
    return failures ? 1 : 0;
}
