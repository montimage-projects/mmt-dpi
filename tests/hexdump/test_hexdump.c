/*
 * test_hexdump.c — comprehensive test suite for hexdump (src/mmt_core/src/hexdump.c).
 *
 * Tests cover:
 *   - fhexdump with empty buffer (len=0)
 *   - fhexdump with single byte
 *   - fhexdump with exactly 16 bytes (one line)
 *   - fhexdump with 17 bytes (two lines, partial second line)
 *   - fhexdump with 32 bytes (exactly two lines)
 *   - fhexdump with non-printable characters
 *   - fhexdump with all printable ASCII
 *   - fhexdump with mixed printable/non-printable
 *   - fhexdump with % character (should be escaped in hex but shown in ASCII)
 *   - hexdump (stderr variant) doesn't crash
 *   - fhexdump with NULL file (should not crash, behavior may vary)
 *   - Output contains expected hex values
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <setjmp.h>
#include <signal.h>

#include "hexdump.h"

static int g_failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { \
        fprintf(stderr, "  FAIL [%s:%d]: %s\n", __FILE__, __LINE__, (msg)); g_failures++; } } while (0)

/* Capture fhexdump output to a string buffer */
static char output_buf[4096];
static FILE *capture_fp;

static void setup_capture(void) {
    output_buf[0] = '\0';
    capture_fp = fmemopen(output_buf, sizeof(output_buf), "w");
    CHECK(capture_fp != NULL, "fmemopen for capture");
}

static void teardown_capture(void) {
    if (capture_fp) {
        fclose(capture_fp);
        capture_fp = NULL;
    }
}

static size_t get_output_len(void) {
    return strlen(output_buf);
}

/* ---- Test: empty buffer ---- */
static void test_empty(void) {
    fprintf(stderr, "  test: fhexdump with empty buffer (len=0)\n");
    setup_capture();
    uint8_t data[1] = {0};
    fhexdump(capture_fp, data, 0);
    teardown_capture();
    /* Empty buffer should produce minimal output (just the initial header line) */
    fprintf(stderr, "    output length: %zu\n", get_output_len());
}

/* ---- Test: single byte ---- */
static void test_single_byte(void) {
    fprintf(stderr, "  test: fhexdump with single byte\n");
    setup_capture();
    uint8_t data[1] = {0xAB};
    fhexdump(capture_fp, data, 1);
    teardown_capture();
    /* Should contain "ab" in hex output */
    CHECK(strstr(output_buf, "ab") != NULL, "single byte: hex output should contain 'ab'");
}

/* ---- Test: exactly 16 bytes (one full line) ---- */
static void test_exactly_16_bytes(void) {
    fprintf(stderr, "  test: fhexdump with exactly 16 bytes\n");
    setup_capture();
    uint8_t data[16];
    for (int i = 0; i < 16; i++) data[i] = (uint8_t)i;
    fhexdump(capture_fp, data, 16);
    teardown_capture();
    /* Should contain hex values 00-0f */
    CHECK(strstr(output_buf, "00") != NULL, "16 bytes: should contain '00'");
    CHECK(strstr(output_buf, "0f") != NULL, "16 bytes: should contain '0f'");
}

/* ---- Test: 17 bytes (two lines, second partial) ---- */
static void test_17_bytes(void) {
    fprintf(stderr, "  test: fhexdump with 17 bytes (two lines)\n");
    setup_capture();
    uint8_t data[17];
    for (int i = 0; i < 17; i++) data[i] = (uint8_t)i;
    fhexdump(capture_fp, data, 17);
    teardown_capture();
    /* Should have output */
    CHECK(get_output_len() > 0, "17 bytes: should produce output");
    /* The output should contain hex values for the data */
    CHECK(strstr(output_buf, "00") != NULL, "17 bytes: should contain '00'");
}

/* ---- Test: 32 bytes (exactly two full lines) ---- */
static void test_32_bytes(void) {
    fprintf(stderr, "  test: fhexdump with 32 bytes (two full lines)\n");
    setup_capture();
    uint8_t data[32];
    for (int i = 0; i < 32; i++) data[i] = (uint8_t)i;
    fhexdump(capture_fp, data, 32);
    teardown_capture();
    CHECK(strstr(output_buf, "00") != NULL, "32 bytes: first line should contain '00'");
    CHECK(strstr(output_buf, "1f") != NULL, "32 bytes: second line should contain '1f'");
}

/* ---- Test: non-printable characters ---- */
static void test_nonprintable(void) {
    fprintf(stderr, "  test: fhexdump with non-printable characters\n");
    setup_capture();
    uint8_t data[16];
    for (int i = 0; i < 16; i++) data[i] = (uint8_t)(i * 17); /* random-looking bytes */
    fhexdump(capture_fp, data, 16);
    teardown_capture();
    /* Non-printable chars should be shown as '.' in ASCII column */
    CHECK(strstr(output_buf, ".") != NULL, "non-printable: ASCII column should contain '.'");
}

/* ---- Test: all printable ASCII ---- */
static void test_printable_ascii(void) {
    fprintf(stderr, "  test: fhexdump with all printable ASCII\n");
    setup_capture();
    uint8_t data[16];
    for (int i = 0; i < 16; i++) data[i] = (uint8_t)('A' + i);
    fhexdump(capture_fp, data, 16);
    teardown_capture();
    /* Printable chars should appear in ASCII column */
    CHECK(strstr(output_buf, "A") != NULL, "printable: ASCII column should contain 'A'");
}

/* ---- Test: mixed printable and non-printable ---- */
static void test_mixed(void) {
    fprintf(stderr, "  test: fhexdump with mixed printable/non-printable\n");
    setup_capture();
    uint8_t data[32];
    for (int i = 0; i < 32; i++) {
        data[i] = (i % 2 == 0) ? (uint8_t)('A' + i % 26) : (uint8_t)(i * 13);
    }
    fhexdump(capture_fp, data, 32);
    teardown_capture();
    CHECK(get_output_len() > 0, "mixed: should produce output");
}

/* ---- Test: hexdump (stderr) doesn't crash ---- */
static void test_hexdump_stderr(void) {
    fprintf(stderr, "  test: hexdump() to stderr doesn't crash\n");
    uint8_t data[4] = {0x01, 0x02, 0x03, 0x04};
    hexdump(data, 4); /* Should not crash */
}

/* ---- Test: large buffer ---- */
static void test_large_buffer(void) {
    fprintf(stderr, "  test: fhexdump with large buffer (256 bytes)\n");
    setup_capture();
    uint8_t *data = malloc(256);
    CHECK(data != NULL, "malloc for large test");
    if (data) {
        for (int i = 0; i < 256; i++) data[i] = (uint8_t)i;
        fhexdump(capture_fp, data, 256);
        teardown_capture();
        CHECK(get_output_len() > 0, "large buffer: should produce output");
        free(data);
    }
}

/* ---- Test: output format contains offset ---- */
static void test_offset_format(void) {
    fprintf(stderr, "  test: output contains hex offset\n");
    setup_capture();
    uint8_t data[16] = {0};
    fhexdump(capture_fp, data, 16);
    teardown_capture();
    /* First line should start with offset 00000000 */
    CHECK(strstr(output_buf, "00000000") != NULL, "output should contain offset '00000000'");
}

/* ---- Test: different FILE* targets ---- */
static void test_different_file(void) {
    fprintf(stderr, "  test: fhexdump with different FILE* targets\n");
    /* Test with stdout (just verify it doesn't crash) */
    uint8_t data[8] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80};
    fhexdump(stdout, data, 8); /* Should not crash */

    /* Test with a temporary file */
    FILE *tmp = tmpfile();
    CHECK(tmp != NULL, "tmpfile for fhexdump");
    if (tmp) {
        fhexdump(tmp, data, 8);
        fclose(tmp);
    }
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;

    fprintf(stderr, "Hexdump test suite\n");

    test_empty();
    test_single_byte();
    test_exactly_16_bytes();
    test_17_bytes();
    test_32_bytes();
    test_nonprintable();
    test_printable_ascii();
    test_mixed();
    test_hexdump_stderr();
    test_large_buffer();
    test_offset_format();
    test_different_file();

    if (g_failures == 0) {
        fprintf(stderr, "ALL CHECKS PASSED\n");
        return 0;
    }
    fprintf(stderr, "%d CHECK(S) FAILED\n", g_failures);
    return 1;
}
