/**
 * @file verification_tests.c
 * @brief Tests for verification, SHA-256/SHA-512, and audit hash chaining.
 */
#define _POSIX_C_SOURCE 200809L

#include "sanitization/verification.h"
#include "sanitization/block_erase.h"
#include "crypto/hash.h"
#include "audit/audit.h"
#include "audit/audit_log.h"
#include "common/error.h"
#include "common/constants.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

static int tests_run    = 0;
static int tests_passed = 0;

#define TEST(name) \
    do { tests_run++; printf("  [ ] " name "... "); fflush(stdout); } while(0)
#define PASS() \
    do { tests_passed++; printf("PASS\n"); } while(0)
#define FAIL(msg) \
    do { printf("FAIL: %s\n", (msg)); } while(0)

/* ─── Helpers ────────────────────────────────────────────────── */

static char *make_temp_file(const uint8_t *fill, size_t size)
{
    char *path = strdup("/tmp/erasecure_vtest_XXXXXX");
    if (!path) return NULL;
    int fd = mkstemp(path);
    if (fd < 0) { free(path); return NULL; }
    uint8_t buf[4096];
    size_t remaining = size;
    while (remaining > 0) {
        size_t chunk = (remaining < sizeof(buf)) ? remaining : sizeof(buf);
        if (fill) memset(buf, (int)*fill, chunk);
        else      memset(buf, 0, chunk);
        ssize_t w = write(fd, buf, chunk);
        if (w <= 0) break;
        remaining -= (size_t)w;
    }
    close(fd);
    return path;
}

/* ─── SHA-256 Tests ──────────────────────────────────────────── */

static void test_sha256_empty(void)
{
    TEST("SHA-256 of empty string matches known value");
    /* SHA-256("") = e3b0c44298fc1c149afb... */
    static const uint8_t expected[32] = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
    };
    uint8_t digest[32];
    ErasecureError err = hash_sha256_buffer((const uint8_t *)"", 0, digest);
    if (err == ERASECURE_OK && memcmp(digest, expected, 32) == 0) PASS();
    else FAIL("SHA-256 empty mismatch");
}

static void test_sha256_abc(void)
{
    TEST("SHA-256(\"abc\") matches known value");
    /* SHA-256("abc") = ba7816bf8f01cfea414140de5dae2ec... */
    static const uint8_t expected[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x2e, 0xc7,
        0x3b, 0x00, 0x36, 0x1b, 0xb9, 0x2e, 0x4f, 0xde,
        0x07, 0xe3, 0x87, 0x2a, 0x48, 0xa7, 0x85, 0xe9
    };
    uint8_t digest[32];
    ErasecureError err = hash_sha256_buffer(
        (const uint8_t *)"abc", 3, digest);
    if (err == ERASECURE_OK && memcmp(digest, expected, 32) == 0) PASS();
    else FAIL("SHA-256(abc) mismatch");
}

static void test_sha512_empty(void)
{
    TEST("SHA-512 of empty string matches known value");
    /* SHA-512("") = cf83e1357eefb8bdf154... */
    static const uint8_t expected[64] = {
        0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd,
        0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07,
        0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc,
        0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce,
        0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0,
        0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
        0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
        0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e
    };
    uint8_t digest[64];
    ErasecureError err = hash_sha512_buffer((const uint8_t *)"", 0, digest);
    if (err == ERASECURE_OK && memcmp(digest, expected, 64) == 0) PASS();
    else FAIL("SHA-512 empty mismatch");
}

static void test_hash_to_hex(void)
{
    TEST("hash_digest_to_hex produces correct hex string");
    uint8_t digest[4] = { 0xDE, 0xAD, 0xBE, 0xEF };
    char hex[9];
    hash_digest_to_hex(digest, 4, hex);
    if (strcmp(hex, "deadbeef") == 0) PASS();
    else FAIL("hex conversion wrong");
}

static void test_sha256_file(void)
{
    TEST("hash_sha256_file hashes a file correctly");
    uint8_t fill = 0x00;
    char *path = make_temp_file(&fill, 1024);
    if (!path) { FAIL("temp file creation failed"); return; }

    uint8_t digest_file[32];
    uint8_t buf[1024];
    memset(buf, 0x00, 1024);
    uint8_t digest_buf[32];

    ErasecureError e1 = hash_sha256_file(path, digest_file);
    ErasecureError e2 = hash_sha256_buffer(buf, 1024, digest_buf);

    unlink(path);
    free(path);

    if (e1 == ERASECURE_OK && e2 == ERASECURE_OK &&
        memcmp(digest_file, digest_buf, 32) == 0) PASS();
    else FAIL("file hash != buffer hash for same content");
}

/* ─── Verification Tests ─────────────────────────────────────── */

static void test_verification_random_not_verifiable(void)
{
    TEST("verify_image_pattern rejects RANDOM pattern");
    uint8_t fill = 0x00;
    char *path = make_temp_file(&fill, 1024);
    if (!path) { FAIL("temp file"); return; }

    VerificationResult vr;
    ErasecureError err = verify_image_pattern(path, ERASE_PATTERN_RANDOM,
                                              512, VERIFY_FULL, &vr);
    unlink(path); free(path);
    if (err == ERASECURE_ERR_UNSUPPORTED) PASS();
    else FAIL("random pattern should return UNSUPPORTED");
}

static void test_verification_confidence_note_set(void)
{
    TEST("verify_image_pattern always sets confidence_note");
    uint8_t fill = 0x00;
    char *path = make_temp_file(&fill, 4096);
    if (!path) { FAIL("temp file"); return; }

    VerificationResult vr;
    verify_image_pattern(path, ERASE_PATTERN_ZERO, 512, VERIFY_FULL, &vr);
    unlink(path); free(path);

    if (strlen(vr.confidence_note) > 0) PASS();
    else FAIL("confidence_note should always be set");
}

/* ─── Audit Hash Chain Tests ─────────────────────────────────── */

static void test_audit_record_finalise_sets_hash(void)
{
    TEST("audit_record_finalize sets non-empty this_record_hash");
    AuditRecord rec;
    audit_record_init(&rec);
    snprintf(rec.case_id,      sizeof(rec.case_id),      "TEST-CASE-001");
    snprintf(rec.operation_id, sizeof(rec.operation_id), "OP-001");

    ErasecureError err = audit_record_finalize(&rec, "");
    if (err == ERASECURE_OK && strlen(rec.this_record_hash) == 64) PASS();
    else FAIL("this_record_hash not set or wrong length");
}

static void test_audit_chain_different_prev(void)
{
    TEST("audit_record_finalize produces different hash for different prev_hash");
    AuditRecord rec1, rec2;
    audit_record_init(&rec1);
    audit_record_init(&rec2);
    snprintf(rec1.case_id, sizeof(rec1.case_id), "TEST");
    snprintf(rec2.case_id, sizeof(rec2.case_id), "TEST");

    audit_record_finalize(&rec1, "aaaaaa");
    audit_record_finalize(&rec2, "bbbbbb");

    if (strcmp(rec1.this_record_hash, rec2.this_record_hash) != 0) PASS();
    else FAIL("different prev_hash should produce different record hash");
}

static void test_audit_chain_tamper_detection(void)
{
    TEST("audit chain: modifying a record changes its hash");
    AuditRecord rec;
    audit_record_init(&rec);
    snprintf(rec.case_id, sizeof(rec.case_id), "TAMPER-TEST");
    audit_record_finalize(&rec, "");

    char original_hash[ERASECURE_SHA256_HEX_LEN];
    snprintf(original_hash, sizeof(original_hash), "%s", rec.this_record_hash);

    /* Tamper with a field */
    snprintf(rec.case_id, sizeof(rec.case_id), "TAMPER-TEST-MODIFIED");
    audit_record_finalize(&rec, "");

    if (strcmp(original_hash, rec.this_record_hash) != 0) PASS();
    else FAIL("tampered record should have different hash");
}

static void test_audit_to_json_non_empty(void)
{
    TEST("audit_record_to_json produces non-empty output");
    AuditRecord rec;
    audit_record_init(&rec);
    snprintf(rec.case_id, sizeof(rec.case_id), "JSON-TEST");
    audit_record_finalize(&rec, "");

    char buf[8192];
    int n = audit_record_to_json(&rec, buf, sizeof(buf));
    if (n > 0 && buf[0] == '{') PASS();
    else FAIL("JSON output malformed");
}

static void test_audit_log_file_append(void)
{
    TEST("audit_log_append_file writes to file successfully");
    char *log_path = strdup("/tmp/erasecure_audit_test_XXXXXX");
    if (!log_path) { FAIL("strdup"); return; }
    int fd = mkstemp(log_path);
    if (fd < 0) { free(log_path); FAIL("mkstemp"); return; }
    close(fd);

    AuditRecord rec;
    audit_record_init(&rec);
    snprintf(rec.case_id, sizeof(rec.case_id), "LOG-TEST");
    audit_record_finalize(&rec, "");

    ErasecureError err = audit_log_append_file(log_path, &rec);

    /* Read back and check */
    FILE *f = fopen(log_path, "r");
    char line[8192];
    int has_content = 0;
    if (f) {
        if (fgets(line, sizeof(line), f)) has_content = 1;
        fclose(f);
    }

    unlink(log_path);
    free(log_path);

    if (err == ERASECURE_OK && has_content) PASS();
    else FAIL("log file empty or write failed");
}

/* ─── Entry point ────────────────────────────────────────────── */

int main(void)
{
    printf("=== Verification, Hash & Audit Tests ===\n");

    test_sha256_empty();
    test_sha256_abc();
    test_sha512_empty();
    test_hash_to_hex();
    test_sha256_file();

    test_verification_random_not_verifiable();
    test_verification_confidence_note_set();

    test_audit_record_finalise_sets_hash();
    test_audit_chain_different_prev();
    test_audit_chain_tamper_detection();
    test_audit_to_json_non_empty();
    test_audit_log_file_append();

    printf("\nResults: %d/%d passed\n\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
