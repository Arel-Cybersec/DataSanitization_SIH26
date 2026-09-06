/**
 * @file crypto_erase_tests.c
 * @brief Unit tests for cryptographic erase module.
 */
#include "sanitization/crypto_erase.h"
#include "device/device.h"
#include "common/error.h"

#include <stdio.h>
#include <string.h>

static int tests_run    = 0;
static int tests_passed = 0;

#define TEST(name) \
    do { tests_run++; printf("  [ ] " name "... "); fflush(stdout); } while(0)
#define PASS() \
    do { tests_passed++; printf("PASS\n"); } while(0)
#define FAIL(msg) \
    do { printf("FAIL: %s\n", (msg)); } while(0)

/* ─── Tests ──────────────────────────────────────────────────── */

static void test_query_non_encrypted_device(void)
{
    TEST("crypto_erase_query returns NOT_ENCRYPTED for plain device");
    StorageDevice dev;
    device_init(&dev);
    dev.encryption_status = ENCRYPTION_STATUS_NOT_ENCRYPTED;
    dev.capabilities.supports_crypto_erase = false;

    CryptoEraseStatus s = crypto_erase_query(&dev);
    if (s == CRYPTO_ERASE_NOT_ENCRYPTED) PASS();
    else FAIL("expected NOT_ENCRYPTED");
}

static void test_query_unknown_encryption(void)
{
    TEST("crypto_erase_query returns NOT_ENCRYPTED for unknown encryption status");
    StorageDevice dev;
    device_init(&dev);
    dev.encryption_status = ENCRYPTION_STATUS_UNKNOWN;
    dev.capabilities.supports_crypto_erase = false;

    CryptoEraseStatus s = crypto_erase_query(&dev);
    if (s == CRYPTO_ERASE_NOT_ENCRYPTED) PASS();
    else FAIL("expected NOT_ENCRYPTED for unknown status");
}

static void test_query_sed_device(void)
{
    TEST("crypto_erase_query returns SUPPORTED for SED device");
    StorageDevice dev;
    device_init(&dev);
    dev.capabilities.supports_crypto_erase = true;

    CryptoEraseStatus s = crypto_erase_query(&dev);
    if (s == CRYPTO_ERASE_SUPPORTED) PASS();
    else FAIL("expected SUPPORTED for SED device");
}

static void test_execute_returns_not_implemented(void)
{
    TEST("crypto_erase_execute returns NOT_IMPLEMENTED (stub)");
    StorageDevice dev;
    device_init(&dev);
    dev.device_type = DEVICE_TYPE_HDD;

    CryptoEraseStatus s = crypto_erase_execute(&dev);
    if (s == CRYPTO_ERASE_NOT_IMPLEMENTED) PASS();
    else FAIL("expected NOT_IMPLEMENTED — real key destruction not yet coded");
}

static void test_execute_null_device(void)
{
    TEST("crypto_erase_execute handles NULL device gracefully");
    CryptoEraseStatus s = crypto_erase_execute(NULL);
    if (s == CRYPTO_ERASE_FAILED) PASS();
    else FAIL("expected FAILED for NULL device");
}

static void test_status_strings_non_null(void)
{
    TEST("crypto_erase_status_str returns non-NULL for all statuses");
    int ok = 1;
    if (!crypto_erase_status_str(CRYPTO_ERASE_SUPPORTED))       ok = 0;
    if (!crypto_erase_status_str(CRYPTO_ERASE_UNSUPPORTED))     ok = 0;
    if (!crypto_erase_status_str(CRYPTO_ERASE_NOT_ENCRYPTED))   ok = 0;
    if (!crypto_erase_status_str(CRYPTO_ERASE_NOT_IMPLEMENTED)) ok = 0;
    if (!crypto_erase_status_str(CRYPTO_ERASE_FAILED))          ok = 0;
    if (!crypto_erase_status_str(CRYPTO_ERASE_SUCCESS))         ok = 0;
    if (ok) PASS(); else FAIL("a status string was NULL");
}

/* ─── Entry point ────────────────────────────────────────────── */

int main(void)
{
    printf("=== Crypto Erase Tests ===\n");
    test_query_non_encrypted_device();
    test_query_unknown_encryption();
    test_query_sed_device();
    test_execute_returns_not_implemented();
    test_execute_null_device();
    test_status_strings_non_null();

    printf("\nResults: %d/%d passed\n\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
