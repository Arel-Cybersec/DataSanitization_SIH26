/**
 * @file device_tests.c
 * @brief Unit tests for device structures and classification.
 */
#include "device/device.h"
#include "device/device_detect.h"
#include "device/device_info.h"
#include "common/error.h"

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

/* Simple test framework */
static int tests_run    = 0;
static int tests_passed = 0;

#define TEST(name) \
    do { tests_run++; printf("  [ ] " name "... "); fflush(stdout); } while(0)

#define PASS() \
    do { tests_passed++; printf("PASS\n"); } while(0)

#define FAIL(msg) \
    do { printf("FAIL: %s\n", (msg)); } while(0)

/* ─── Tests ──────────────────────────────────────────────────── */

static void test_device_init_zeroes(void)
{
    TEST("device_init sets safe defaults");
    StorageDevice dev;
    /* Fill with garbage first */
    memset(&dev, 0xAB, sizeof(dev));
    device_init(&dev);

    int ok = 1;
    if (dev.device_type   != DEVICE_TYPE_UNKNOWN)  ok = 0;
    if (dev.transport_type != TRANSPORT_UNKNOWN)    ok = 0;
    if (dev.is_read_only  != false)                ok = 0;
    if (dev.is_removable  != false)                ok = 0;
    if (dev.logical_sector_size  != 512U)          ok = 0;
    if (dev.physical_sector_size != 512U)          ok = 0;
    if (dev.capacity_bytes != 0)                   ok = 0;

    if (ok) PASS(); else FAIL("init fields incorrect");
}

static void test_device_type_strings(void)
{
    TEST("device_type_str returns non-NULL for all types");
    int ok = 1;
    if (!device_type_str(DEVICE_TYPE_UNKNOWN))    ok = 0;
    if (!device_type_str(DEVICE_TYPE_HDD))        ok = 0;
    if (!device_type_str(DEVICE_TYPE_SATA_SSD))   ok = 0;
    if (!device_type_str(DEVICE_TYPE_NVME_SSD))   ok = 0;
    if (!device_type_str(DEVICE_TYPE_USB_HDD))    ok = 0;
    if (!device_type_str(DEVICE_TYPE_USB_SSD))    ok = 0;
    if (!device_type_str(DEVICE_TYPE_USB_FLASH))  ok = 0;
    if (!device_type_str(DEVICE_TYPE_SD_CARD))    ok = 0;
    if (ok) PASS(); else FAIL("a type string was NULL");
}

static void test_transport_type_strings(void)
{
    TEST("device_transport_str returns non-NULL for all transports");
    int ok = 1;
    if (!device_transport_str(TRANSPORT_UNKNOWN)) ok = 0;
    if (!device_transport_str(TRANSPORT_SATA))    ok = 0;
    if (!device_transport_str(TRANSPORT_NVME))    ok = 0;
    if (!device_transport_str(TRANSPORT_USB))     ok = 0;
    if (!device_transport_str(TRANSPORT_SD))      ok = 0;
    if (ok) PASS(); else FAIL("a transport string was NULL");
}

static void test_sanitization_method_strings(void)
{
    TEST("sanitization_method_str covers all methods");
    int ok = 1;
    if (!sanitization_method_str(SANITIZE_METHOD_NONE))          ok = 0;
    if (!sanitization_method_str(SANITIZE_METHOD_BLOCK_ERASE))   ok = 0;
    if (!sanitization_method_str(SANITIZE_METHOD_CRYPTO_ERASE))  ok = 0;
    if (!sanitization_method_str(SANITIZE_METHOD_DEVICE_NATIVE)) ok = 0;
    if (ok) PASS(); else FAIL("a method string was NULL");
}

static void test_path_is_block_device(void)
{
    TEST("device_path_is_block_device detects /dev/sda");
    bool r = device_path_is_block_device("/dev/sda");
    if (r) PASS(); else FAIL("should detect /dev/sda as block device");
}

static void test_path_not_block_device(void)
{
    TEST("device_path_is_block_device rejects /tmp/test.img");
    bool r = device_path_is_block_device("/tmp/test.img");
    if (!r) PASS(); else FAIL("/tmp/test.img should NOT be a block device path");
}

static void test_path_nvme_is_block_device(void)
{
    TEST("device_path_is_block_device detects /dev/nvme0n1");
    bool r = device_path_is_block_device("/dev/nvme0n1");
    if (r) PASS(); else FAIL("/dev/nvme0n1 should be detected as block device");
}

static void test_classify_nvme(void)
{
    TEST("device_classify sets NVMe type for nvme0n1");
    StorageDevice dev;
    device_init(&dev);
    device_classify("nvme0n1", &dev);
    int ok = (dev.device_type == DEVICE_TYPE_NVME_SSD &&
              dev.transport_type == TRANSPORT_NVME);
    if (ok) PASS(); else FAIL("NVMe classification failed");
}

static void test_classify_mmcblk(void)
{
    TEST("device_classify sets SD_CARD type for mmcblk0");
    StorageDevice dev;
    device_init(&dev);
    device_classify("mmcblk0", &dev);
    int ok = (dev.device_type == DEVICE_TYPE_SD_CARD &&
              dev.transport_type == TRANSPORT_SD);
    if (ok) PASS(); else FAIL("MMC/SD classification failed");
}

/* ─── Entry point ────────────────────────────────────────────── */

int main(void)
{
    printf("=== Device Tests ===\n");
    test_device_init_zeroes();
    test_device_type_strings();
    test_transport_type_strings();
    test_sanitization_method_strings();
    test_path_is_block_device();
    test_path_not_block_device();
    test_path_nvme_is_block_device();
    test_classify_nvme();
    test_classify_mmcblk();

    printf("\nResults: %d/%d passed\n\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
