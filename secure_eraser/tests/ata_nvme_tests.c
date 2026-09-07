/**
 * @file ata_nvme_tests.c
 * @brief Unit tests for ATA/NVMe pass-through, SED capability, and crypto erase.
 */
#define _POSIX_C_SOURCE 200809L

#include "ata/ata_passthrough.h"
#include "ata/ata_identify.h"
#include "ata/ata_sanitize.h"
#include "nvme/nvme_passthrough.h"
#include "nvme/nvme_identify.h"
#include "nvme/nvme_sanitize.h"
#include "sanitization/crypto_erase.h"
#include "crypto/key_management.h"
#include "device/device.h"
#include "common/error.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

static int g_tests_run = 0;
static int g_tests_passed = 0;

#define TEST_ASSERT(cond, name) do { \
    g_tests_run++; \
    if (cond) { \
        g_tests_passed++; \
        printf("  [PASS] %s\n", name); \
    } else { \
        printf("  [FAIL] %s\n", name); \
    } \
} while (0)

int main(void)
{
    printf("=== Running Real ATA, NVMe & Crypto Erase Unit Tests ===\n");

    /* Test 1: ATA Command Init */
    AtaCommand ata_cmd;
    ata_command_init(&ata_cmd);
    TEST_ASSERT(ata_cmd.timeout_ms > 0,
                "ata_command_init sets non-zero default timeout");

    /* Test 2: NVMe Admin Command Init */
    NvmeAdminCommand nvme_cmd;
    nvme_admin_cmd_init(&nvme_cmd);
    TEST_ASSERT(nvme_cmd.timeout_ms > 0,
                "nvme_admin_cmd_init sets non-zero default timeout");

    /* Test 3: ATA Sanitize Query on safe dummy path */
    AtaSanitizeCapabilities ata_caps;
    ErasecureError ata_err = ata_sanitize_query("/dev/nonexistent_dummy_sata", &ata_caps);
    TEST_ASSERT(ata_err != ERASECURE_OK,
                "ata_sanitize_query handles invalid/nonexistent path safely");

    /* Test 4: NVMe Sanitize Query on safe dummy path */
    NvmeSanitizeCapabilities nvme_caps;
    ErasecureError nvme_err = nvme_sanitize_query("/dev/nonexistent_dummy_nvme", &nvme_caps);
    TEST_ASSERT(nvme_err != ERASECURE_OK,
                "nvme_sanitize_query handles invalid/nonexistent path safely");

    /* Test 5: Synthetic Key Cryptographic Destruction */
    uint8_t key[32];
    for (size_t i = 0; i < sizeof(key); ++i) {
        key[i] = (uint8_t)(i + 0x42);
    }
    CryptoEraseStatus ces = crypto_erase_synthetic_key(key, sizeof(key));
    bool all_zero = true;
    for (size_t i = 0; i < sizeof(key); ++i) {
        if (key[i] != 0) all_zero = false;
    }
    TEST_ASSERT(ces == CRYPTO_ERASE_SUCCESS && all_zero,
                "crypto_erase_synthetic_key zeroes key memory and returns SUCCESS");

    /* Test 6: LUKS Volume Header Detection on synthetic buffer */
    char luks_tmp[] = "tmp_luks_test_XXXXXX";
    int fd = mkstemp(luks_tmp);
    if (fd >= 0) {
        uint8_t luks_header[512];
        memset(luks_header, 0, sizeof(luks_header));
        /* Magic: 'L', 'U', 'K', 'S', 0xba, 0xbe, version 2 */
        luks_header[0] = 'L';
        luks_header[1] = 'U';
        luks_header[2] = 'K';
        luks_header[3] = 'S';
        luks_header[4] = 0xba;
        luks_header[5] = 0xbe;
        luks_header[6] = 0x00;
        luks_header[7] = 0x02; /* LUKS2 */
        ssize_t w = write(fd, luks_header, sizeof(luks_header));
        (void)w;
        close(fd);

        EncryptedVolumeType vol_type = ENCRYPTED_VOL_NONE;
        ErasecureError lerr = key_mgmt_detect_luks(luks_tmp, &vol_type);
        TEST_ASSERT(lerr == ERASECURE_OK && vol_type == ENCRYPTED_VOL_LUKS2,
                    "key_mgmt_detect_luks successfully detects synthetic LUKS2 volume");
        unlink(luks_tmp);
    }

    /* Test 7: String conversions */
    const char *sed_str = key_mgmt_capability_str(KEY_MGMT_SED_DETECTED);
    const char *vol_str = encrypted_volume_type_str(ENCRYPTED_VOL_LUKS2);
    TEST_ASSERT(sed_str && strlen(sed_str) > 0 && vol_str && strlen(vol_str) > 0,
                "key_mgmt string helpers produce non-empty strings");

    /* Test 8: Crypto Erase Status strings */
    const char *ces_str = crypto_erase_status_str(CRYPTO_ERASE_SUCCESS);
    TEST_ASSERT(ces_str && strcmp(ces_str, "Success") == 0,
                "crypto_erase_status_str returns correct label for SUCCESS");

    printf("ATA/NVMe/Crypto Tests Summary: %d/%d passed.\n", g_tests_passed, g_tests_run);
    return (g_tests_passed == g_tests_run) ? 0 : 1;
}
