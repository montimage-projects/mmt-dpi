/*
 * arena_alloc_test — unit test for the per-flow arena (slab) allocator (#20).
 *
 * Part of the MMT-DPI Master Improvement Plan, Phase 5 (P2).
 *
 * Issue #20 introduces a per-flow arena allocator (mmt_arena_create/alloc/
 * reset/destroy in src/mmt_core/src/memory.c) used to back the per-TCP-segment
 * node + payload copies so that per-packet malloc/free churn collapses into a
 * single create/destroy pair per flow.
 *
 * This test exercises the allocator directly and asserts:
 *   1. A fresh arena hands out distinct, writable, 16-byte-aligned blocks.
 *   2. Block contents are independent (no overlap / corruption) once every
 *      block has been written and read back.
 *   3. The arena grows correctly past its default block size (many small
 *      allocations) and serves a single oversized request (> block size).
 *   4. mmt_arena_reset() rewinds the arena for reuse.
 *   5. NULL-safety: alloc on a NULL arena returns NULL; reset/destroy(NULL)
 *      are no-ops; a zero-size request still returns a usable, distinct block.
 *
 * Every returned block is fully written and verified, so when the test is built
 * with AddressSanitizer (see run_arena_alloc_test.sh) any out-of-bounds write
 * within an arena block is caught. With -fno-sanitize-recover=all a sanitizer
 * hit aborts the process; a clean exit 0 with all assertions passing is success.
 *
 * Build (see run_arena_alloc_test.sh):
 *   gcc -g -O1 -fsanitize=address,undefined -o arena_alloc_test \
 *       arena_alloc_test.c -I<prefix>/dpi/include \
 *       -L<prefix>/dpi/lib -lmmt_core -ldl -lpthread -lm
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "mmt_core.h"

static int failures = 0;

#define CHECK(cond, msg)                                            \
    do {                                                            \
        if (cond) {                                                 \
            printf("  ok   - %s\n", (msg));                         \
        } else {                                                    \
            printf("  FAIL - %s\n", (msg));                         \
            failures++;                                             \
        }                                                           \
    } while (0)

#define ALIGN 16u

int main(void)
{
    printf("arena_alloc_test: per-flow arena allocator (#20)\n");

    /* 1. Basic create + a handful of distinct, aligned, writable blocks. */
    mmt_arena_t *a = mmt_arena_create(0); /* 0 -> default block size */
    CHECK(a != NULL, "mmt_arena_create(0) returns an arena");

    void *b1 = mmt_arena_alloc(a, 13);
    void *b2 = mmt_arena_alloc(a, 1);
    void *b3 = mmt_arena_alloc(a, 200);
    CHECK(b1 && b2 && b3, "three small allocations succeed");
    CHECK(b1 != b2 && b2 != b3 && b1 != b3, "allocations are distinct");
    CHECK(((uintptr_t)b1 % ALIGN) == 0 &&
          ((uintptr_t)b2 % ALIGN) == 0 &&
          ((uintptr_t)b3 % ALIGN) == 0, "allocations are 16-byte aligned");

    /* Write each block fully; if blocks overlapped or ran short, a later
     * read-back would mismatch (and ASan would flag an OOB write). */
    memset(b1, 0xA1, 13);
    memset(b2, 0xB2, 1);
    memset(b3, 0xC3, 200);
    CHECK(((uint8_t*)b1)[12] == 0xA1 && ((uint8_t*)b2)[0] == 0xB2 &&
          ((uint8_t*)b3)[199] == 0xC3, "block contents independent after write");

    /* 2. Grow past the default block size with many small allocations, each
     *    tagged with its index and verified at the end (no cross-corruption). */
    enum { N = 5000 };
    uint8_t *blocks[N];
    int ok_alloc = 1;
    for (int i = 0; i < N; i++) {
        blocks[i] = (uint8_t *) mmt_arena_alloc(a, 32);
        if (!blocks[i]) { ok_alloc = 0; break; }
        memset(blocks[i], (uint8_t)(i & 0xFF), 32);
        if (((uintptr_t)blocks[i] % ALIGN) != 0) { ok_alloc = 0; break; }
    }
    CHECK(ok_alloc, "5000 aligned allocations across many blocks succeed");
    int integrity = 1;
    for (int i = 0; i < N; i++) {
        for (int j = 0; j < 32; j++) {
            if (blocks[i][j] != (uint8_t)(i & 0xFF)) { integrity = 0; break; }
        }
        if (!integrity) break;
    }
    CHECK(integrity, "all 5000 blocks retain their contents (no overlap)");

    /* 3. A single oversized request (much larger than the default block). */
    size_t big = 256 * 1024;
    uint8_t *huge = (uint8_t *) mmt_arena_alloc(a, big);
    CHECK(huge != NULL, "oversized (256 KiB) allocation succeeds");
    if (huge) {
        memset(huge, 0x5A, big);
        CHECK(huge[0] == 0x5A && huge[big - 1] == 0x5A,
              "oversized block fully writable");
    }

    /* 4. reset() rewinds for reuse; subsequent allocs still work. */
    mmt_arena_reset(a);
    void *r1 = mmt_arena_alloc(a, 64);
    CHECK(r1 != NULL, "allocation after reset succeeds");
    if (r1) memset(r1, 0x77, 64);

    mmt_arena_destroy(a);
    CHECK(1, "mmt_arena_destroy frees the arena (no crash)");

    /* 5. NULL-safety + zero-size behaviour. */
    CHECK(mmt_arena_alloc(NULL, 16) == NULL, "alloc on NULL arena returns NULL");
    mmt_arena_reset(NULL);   /* must be a no-op */
    mmt_arena_destroy(NULL); /* must be a no-op */
    CHECK(1, "reset/destroy on NULL arena are no-ops (no crash)");

    mmt_arena_t *z = mmt_arena_create(0);
    void *z1 = mmt_arena_alloc(z, 0);
    void *z2 = mmt_arena_alloc(z, 0);
    CHECK(z1 != NULL && z2 != NULL && z1 != z2,
          "zero-size allocations return distinct usable blocks");
    mmt_arena_destroy(z);

    if (failures == 0) {
        printf("arena_alloc_test: PASS\n");
        return 0;
    }
    printf("arena_alloc_test: FAIL (%d assertion(s) failed)\n", failures);
    return 1;
}
