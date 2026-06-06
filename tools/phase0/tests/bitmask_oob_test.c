/*
 * bitmask_oob_test — unit test for the protocol bitmask sizing/coverage fix
 * (issues #51 and #52, Phase 2 memory-safety).
 *
 * Root cause: mmt_protocol_bitmask_struct.bitmask[] was [10] (640 bits, valid
 * protocol ids 0..639). Protocol ids >= 640 -- PROTO_MQTT (657), PROTO_INT
 * (658), PROTO_QUIC_IETF (661) -- index bitmask[10], one element past the end:
 * a global/heap buffer overflow. In addition most per-word bitmask macros only
 * touched words 0..6 (448 bits), so ids >= 448 were silently ignored.
 *
 * The fix resizes the array to MMT_PROTOCOL_BITMASK_NUM_WORDS (16 words ->
 * 1024 bits, covering PROTO_MAX_IDENTIFIER == 1000) and extends every per-word
 * macro to span all words.
 *
 * This test exercises the bitmask macros directly (header-only; no library link
 * needed) and asserts:
 *   1. The array is large enough for the full protocol-id range.
 *   2. MMT_ADD_PROTOCOL_TO_BITMASK / MMT_SAVE_AS_BITMASK for the offending high
 *      ids (657/658/661) and the largest id (PROTO_MAX_IDENTIFIER-1) set the
 *      expected bit and do NOT write out of bounds.
 *   3. MMT_COMPARE_PROTOCOL_TO_BITMASK and MMT_BITMASK_COMPARE see bits in the
 *      high words (>= word 7) that the old 0..6 macros would have missed.
 *   4. MMT_SAVE_AS_BITMASK clears ALL words (not just 0..6) before setting one.
 *   5. MMT_BITMASK_RESET / IS_ZERO / ADD / DEL / SET / AND cover every word.
 *
 * The bitmask under test is heap-allocated at exactly sizeof(*) so AddressSan
 * brackets it precisely: any write past the array end lands in the redzone and
 * (with -fno-sanitize-recover=all) aborts. A clean exit 0 with all assertions
 * passing is success. See run_bitmask_oob_test.sh.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "mmt_core.h"                       /* PROTO_MAX_IDENTIFIER */
#include "mmt_tcpip_internal_defs_macros.h" /* the bitmask struct + macros */

static int failures = 0;

#define CHECK(cond, msg)                                              \
    do {                                                              \
        if (!(cond)) {                                               \
            fprintf(stderr, "  ✗ FAIL: %s\n", (msg));               \
            failures++;                                              \
        } else {                                                     \
            fprintf(stderr, "  ✓ %s\n", (msg));                     \
        }                                                            \
    } while (0)

int main(void) {
    fprintf(stderr, "bitmask_oob_test: protocol bitmask sizing/coverage (#51,#52)\n");

    /* 1. Array must cover the full protocol-id space. */
    CHECK(MMT_PROTOCOL_BITMASK_NUM_WORDS * 64 >= PROTO_MAX_IDENTIFIER,
          "bitmask covers full PROTO_MAX_IDENTIFIER range");
    CHECK((657 >> 6) < MMT_PROTOCOL_BITMASK_NUM_WORDS,
          "PROTO_MQTT (657) word index is in bounds");
    CHECK((658 >> 6) < MMT_PROTOCOL_BITMASK_NUM_WORDS,
          "PROTO_INT (658) word index is in bounds");
    CHECK((661 >> 6) < MMT_PROTOCOL_BITMASK_NUM_WORDS,
          "PROTO_QUIC_IETF (661) word index is in bounds");

    /* Heap-allocate exactly one struct so ASan brackets it precisely. */
    mmt_protocol_bitmask_t *bm = malloc(sizeof(*bm));
    if (bm == NULL) { perror("malloc"); return 2; }

    /* The high ids that used to overflow bitmask[10]. PROTO_MAX_IDENTIFIER-1 is
     * the largest id the array must hold. */
    const uint32_t high_ids[] = { 657u, 658u, 661u, PROTO_MAX_IDENTIFIER - 1u };
    const size_t n_high = sizeof(high_ids) / sizeof(high_ids[0]);

    /* 2 + 3. ADD each high id, then confirm it is detected (no OOB). */
    MMT_BITMASK_RESET(*bm);
    for (size_t i = 0; i < n_high; i++) {
        MMT_ADD_PROTOCOL_TO_BITMASK(*bm, high_ids[i]); /* OOB write if undersized */
    }
    for (size_t i = 0; i < n_high; i++) {
        char msg[96];
        snprintf(msg, sizeof(msg),
                 "MMT_COMPARE_PROTOCOL_TO_BITMASK sees id %u (word %u)",
                 high_ids[i], high_ids[i] >> 6);
        CHECK(MMT_COMPARE_PROTOCOL_TO_BITMASK(*bm, high_ids[i]) != 0, msg);
    }

    /* 3. MMT_BITMASK_COMPARE must see a high-word bit (>= word 7), which the
     * old 0..6 macro could not. */
    {
        mmt_protocol_bitmask_t other;
        MMT_SAVE_AS_BITMASK(other, 661u); /* word 10 */
        CHECK(MMT_BITMASK_COMPARE(*bm, other) != 0,
              "MMT_BITMASK_COMPARE detects overlap in a high word");
    }

    /* 4. MMT_SAVE_AS_BITMASK must clear ALL words then set exactly one bit. */
    MMT_SAVE_AS_BITMASK(*bm, 661u);
    {
        int only_one = 1, set_word = 661 >> 6;
        for (int w = 0; w < MMT_PROTOCOL_BITMASK_NUM_WORDS; w++) {
            uint64_t expect = (w == set_word)
                                  ? (((uint64_t)1) << (661 & 0x3F))
                                  : 0u;
            if (bm->bitmask[w] != expect) only_one = 0;
        }
        CHECK(only_one,
              "MMT_SAVE_AS_BITMASK clears all words and sets exactly one bit");
    }

    /* 5a. MMT_BITMASK_RESET clears every word. */
    {
        mmt_protocol_bitmask_t z;
        MMT_BITMASK_SET_ALL(z);          /* dirty every word */
        MMT_BITMASK_RESET(z);
        CHECK(MMT_BITMASK_IS_ZERO(z),
              "MMT_BITMASK_RESET + IS_ZERO cover every word");
    }

    /* 5b. ADD / DEL / SET round-trip across a high word. */
    {
        mmt_protocol_bitmask_t a, b;
        MMT_BITMASK_RESET(a);
        MMT_SAVE_AS_BITMASK(b, 999u);    /* word 15 */
        MMT_BITMASK_ADD(a, b);
        CHECK(MMT_COMPARE_PROTOCOL_TO_BITMASK(a, 999u) != 0,
              "MMT_BITMASK_ADD propagates a word-15 bit");
        MMT_BITMASK_DEL(a, b);
        CHECK(MMT_BITMASK_IS_ZERO(a),
              "MMT_BITMASK_DEL clears the word-15 bit");
        MMT_BITMASK_SET(a, b);
        CHECK(MMT_BITMASK_MATCH(a, b),
              "MMT_BITMASK_SET + MATCH cover every word");
    }

    /* 5c. MMT_BITMASK_AND keeps only common high-word bits. */
    {
        mmt_protocol_bitmask_t a, b;
        MMT_SAVE_AS_BITMASK(a, 999u);
        MMT_SAVE_AS_BITMASK(b, 998u);
        MMT_BITMASK_AND(a, b);           /* disjoint -> empty */
        CHECK(MMT_BITMASK_IS_ZERO(a),
              "MMT_BITMASK_AND clears non-common high-word bits");
    }

    free(bm);

    if (failures != 0) {
        fprintf(stderr, "bitmask_oob_test: %d FAILURE(S)\n", failures);
        return 1;
    }
    fprintf(stderr, "bitmask_oob_test: all checks PASS\n");
    return 0;
}
