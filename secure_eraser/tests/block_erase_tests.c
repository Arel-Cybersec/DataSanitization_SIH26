/**
 * @file block_erase_tests.c
 * @brief Unit tests for block erase on disk images.
 *
 * All tests use temporary files. No real devices are touched.
 */
#define _POSIX_C_SOURCE 200809L

#include "sanitization/block_erase.h"
#include "sanitization/verification.h"
#include "device/device_detect.h"
#include "common/constants.h"
#include "common/error.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <assert.h>

static int tests_run    = 0;
static int tests_passed = 0;

#define TEST(name) \
    do { tests_run++; printf("  [ ] " name "... "); fflush(stdout); } while(0)
#define PASS() \
    do { tests_passed++; printf("PASS\n"); } while(0)
#define FAIL(msg) \
    do { printf("FAIL: %s\n", (msg)); } while(0)

/* ─── Helpers ────────────────────────────────────────────────── */

/** Create a temporary file of given size filled with 0xAA. Returns path. */
static char *create_test_image(size_t size_bytes)
{
    char *path = strdup("/tmp/erasecure_test_XXXXXX");
    if (!path) return NULL;

    int fd = mkstemp(path);
    if (fd < 0) { free(path); return NULL; }

    /* Fill with 0xAA sentinel */
    uint8_t buf[4096];
    memset(buf, 0xAA, sizeof(buf));
    size_t remaining = size_bytes;
    while (remaining > 0) {
        size_t chunk = (remaining < sizeof(buf)) ? remaining : sizeof(buf);
        ssize_t w = write(fd, buf, chunk);
        if (w <= 0) break;
        remaining -= (size_t)w;
    }
    close(fd);
    return path;
}

static void remove_test_image(const char *path)
{
    if (path) unlink(path);
}

/** Read the first `count` bytes of a file into buf. */
static int read_file_bytes(const char *path, uint8_t *buf, size_t count)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    size_t n = fread(buf, 1, count, f);
    fclose(f);
    return (n == count) ? 0 : -1;
}

/* ─── Tests ──────────────────────────────────────────────────── */

static void test_safety_block_real_device(void)
{
    TEST("block_erase_image rejects /dev/sda");
    BlockEraseOptions opts;
    block_erase_options_init(&opts);
    BlockEraseResult result;

    ErasecureError err = block_erase_image("/dev/sda", &opts, &result);
    if (err == ERASECURE_ERR_REAL_DEVICE_PATH) PASS();
    else FAIL("should return ERASECURE_ERR_REAL_DEVICE_PATH");
}

static void test_safety_block_nvme(void)
{
    TEST("block_erase_image rejects /dev/nvme0n1");
    BlockEraseOptions opts;
    block_erase_options_init(&opts);
    BlockEraseResult result;

    ErasecureError err = block_erase_image("/dev/nvme0n1", &opts, &result);
    if (err == ERASECURE_ERR_REAL_DEVICE_PATH) PASS();
    else FAIL("should return ERASECURE_ERR_REAL_DEVICE_PATH");
}

static void test_zero_pattern(void)
{
    TEST("block_erase_image zero pattern fills with 0x00");

    char *path = create_test_image(64 * 1024);  /* 64 KiB */
    if (!path) { FAIL("could not create test image"); return; }

    BlockEraseOptions opts;
    block_erase_options_init(&opts);
    opts.pattern    = ERASE_PATTERN_ZERO;
    opts.block_size = 4096;
    opts.passes     = 1;

    BlockEraseResult result;
    ErasecureError err = block_erase_image(path, &opts, &result);

    int ok = 0;
    if (err == ERASECURE_OK) {
        uint8_t buf[256];
        if (read_file_bytes(path, buf, sizeof(buf)) == 0) {
            ok = 1;
            for (size_t i = 0; i < sizeof(buf); ++i) {
                if (buf[i] != 0x00) { ok = 0; break; }
            }
        }
    }

    remove_test_image(path);
    free(path);
    if (ok) PASS(); else FAIL("bytes not all 0x00");
}

static void test_one_pattern(void)
{
    TEST("block_erase_image one pattern fills with 0xFF");

    char *path = create_test_image(64 * 1024);
    if (!path) { FAIL("could not create test image"); return; }

    BlockEraseOptions opts;
    block_erase_options_init(&opts);
    opts.pattern    = ERASE_PATTERN_ONE;
    opts.block_size = 4096;
    opts.passes     = 1;

    BlockEraseResult result;
    ErasecureError err = block_erase_image(path, &opts, &result);

    int ok = 0;
    if (err == ERASECURE_OK) {
        uint8_t buf[256];
        if (read_file_bytes(path, buf, sizeof(buf)) == 0) {
            ok = 1;
            for (size_t i = 0; i < sizeof(buf); ++i) {
                if (buf[i] != 0xFF) { ok = 0; break; }
            }
        }
    }

    remove_test_image(path);
    free(path);
    if (ok) PASS(); else FAIL("bytes not all 0xFF");
}

static void test_random_pattern(void)
{
    TEST("block_erase_image random pattern completes without error");

    char *path = create_test_image(64 * 1024);
    if (!path) { FAIL("could not create test image"); return; }

    BlockEraseOptions opts;
    block_erase_options_init(&opts);
    opts.pattern    = ERASE_PATTERN_RANDOM;
    opts.block_size = 4096;
    opts.passes     = 1;

    BlockEraseResult result;
    ErasecureError err = block_erase_image(path, &opts, &result);

    /* Also check it actually changed something from the sentinel 0xAA */
    int changed = 0;
    if (err == ERASECURE_OK) {
        uint8_t buf[256];
        if (read_file_bytes(path, buf, sizeof(buf)) == 0) {
            for (size_t i = 0; i < sizeof(buf); ++i) {
                if (buf[i] != 0xAA) { changed = 1; break; }
            }
        }
    }

    remove_test_image(path);
    free(path);
    if (err == ERASECURE_OK && changed) PASS();
    else FAIL("random erase failed or produced no change");
}

static void test_multi_pass(void)
{
    TEST("block_erase_image multi-pass (3) zero pattern");

    char *path = create_test_image(32 * 1024);
    if (!path) { FAIL("could not create test image"); return; }

    BlockEraseOptions opts;
    block_erase_options_init(&opts);
    opts.pattern = ERASE_PATTERN_ZERO;
    opts.passes  = 3;

    BlockEraseResult result;
    ErasecureError err = block_erase_image(path, &opts, &result);

    remove_test_image(path);
    free(path);

    int ok = (err == ERASECURE_OK && result.passes_completed == 3);
    if (ok) PASS(); else FAIL("multi-pass did not complete 3 passes");
}

static void test_bytes_written_correct(void)
{
    TEST("block_erase_image reports correct bytes_written");

    size_t img_size = 128 * 1024;  /* 128 KiB */
    char *path = create_test_image(img_size);
    if (!path) { FAIL("could not create test image"); return; }

    BlockEraseOptions opts;
    block_erase_options_init(&opts);
    opts.pattern = ERASE_PATTERN_ZERO;
    opts.passes  = 2;

    BlockEraseResult result;
    ErasecureError err = block_erase_image(path, &opts, &result);

    remove_test_image(path);
    free(path);

    uint64_t expected = (uint64_t)img_size * 2;
    int ok = (err == ERASECURE_OK && result.bytes_written == expected);
    if (ok) PASS(); else FAIL("bytes_written does not match expected");
}

static void test_verify_zero_pass(void)
{
    TEST("verify_image_pattern PASS after zero erase");

    char *path = create_test_image(64 * 1024);
    if (!path) { FAIL("could not create test image"); return; }

    BlockEraseOptions opts;
    block_erase_options_init(&opts);
    opts.pattern    = ERASE_PATTERN_ZERO;
    opts.block_size = 4096;

    BlockEraseResult result;
    block_erase_image(path, &opts, &result);

    VerificationResult vr;
    verify_image_pattern(path, ERASE_PATTERN_ZERO, 4096, VERIFY_FULL, &vr);

    remove_test_image(path);
    free(path);

    if (vr.verification_passed && vr.blocks_failed == 0) PASS();
    else FAIL("verification should PASS after zero erase");
}

static void test_verify_detects_corruption(void)
{
    TEST("verify_image_pattern FAIL when image is not zeroed");

    char *path = create_test_image(64 * 1024);  /* filled with 0xAA */
    if (!path) { FAIL("could not create test image"); return; }

    VerificationResult vr;
    verify_image_pattern(path, ERASE_PATTERN_ZERO, 4096, VERIFY_FULL, &vr);

    remove_test_image(path);
    free(path);

    if (!vr.verification_passed && vr.blocks_failed > 0) PASS();
    else FAIL("verification should FAIL on non-zero image");
}

static void test_options_init_defaults(void)
{
    TEST("block_erase_options_init sets sane defaults");
    BlockEraseOptions opts;
    block_erase_options_init(&opts);
    int ok = (opts.pattern == ERASE_PATTERN_ZERO &&
              opts.block_size == ERASECURE_DEFAULT_BLOCK_SIZE &&
              opts.passes == ERASECURE_DEFAULT_PASSES);
    if (ok) PASS(); else FAIL("default options incorrect");
}

/* ─── Entry point ────────────────────────────────────────────── */

int main(void)
{
    printf("=== Block Erase Tests ===\n");
    test_safety_block_real_device();
    test_safety_block_nvme();
    test_zero_pattern();
    test_one_pattern();
    test_random_pattern();
    test_multi_pass();
    test_bytes_written_correct();
    test_verify_zero_pass();
    test_verify_detects_corruption();
    test_options_init_defaults();

    printf("\nResults: %d/%d passed\n\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
