/**
 * @file ssd_sanitizer.h
 * @brief SSD-specific sanitization module (SATA SSD and NVMe SSD).
 *
 * CRITICAL NOTICE:
 *   Logical block overwrite (writing 0x00 or random bytes to every LBA)
 *   does NOT guarantee physical NAND cell erasure on SSDs.  The Flash
 *   Translation Layer (FTL) may remap writes to different physical pages,
 *   leaving the original data intact on unmapped pages.  Over-provisioned
 *   areas, bad-block tables, and wear-levelling regions may also retain
 *   data that is inaccessible to the host.
 *
 *   True physical sanitization of SSDs requires:
 *     - SATA SSD: ATA SECURITY ERASE UNIT (enhanced) or ATA Sanitize.
 *     - NVMe SSD: NVMe Format NVM (ses=2) or NVMe Sanitize (Block Erase).
 *
 *   Neither of the above is implemented in this version.  All device-native
 *   operations return SSD_SANITIZE_NOT_IMPLEMENTED.
 */
#ifndef ERASECURE_SSD_SANITIZER_H
#define ERASECURE_SSD_SANITIZER_H

#include "device/device.h"
#include "sanitization/sanitizer.h"
#include "common/error.h"

/* ─── SSD sanitization status ────────────────────────────────── */
typedef enum {
    SSD_SANITIZE_SUCCESS             = 0,
    SSD_SANITIZE_UNSUPPORTED         = 1,
    SSD_SANITIZE_NOT_IMPLEMENTED     = 2,
    SSD_SANITIZE_FAILED              = 3,
    SSD_SANITIZE_DEVICE_ERROR        = 4,
    SSD_SANITIZE_LOGICAL_ONLY_WARN   = 5,  /* Block erase done, NAND NOT guaranteed */
} SsdSanitizeStatus;

/**
 * @brief Check whether this module can handle the device.
 * @return true for DEVICE_TYPE_SATA_SSD or DEVICE_TYPE_NVME_SSD.
 */
bool ssd_can_handle(const StorageDevice *device);

/**
 * @brief Check whether a sanitization method is available for this SSD.
 */
bool ssd_supports_method(const StorageDevice *device, SanitizationMethod method);

/**
 * @brief Run SSD sanitization.
 *
 * BLOCK_ERASE on test images: implemented (with NAND caveat noted in result).
 * DEVICE_NATIVE_SANITIZE (SATA): NOT IMPLEMENTED.
 * DEVICE_NATIVE_SANITIZE (NVMe): NOT IMPLEMENTED.
 * CRYPTO_ERASE: delegated to crypto_erase module.
 */
ErasecureError ssd_sanitize(const StorageDevice *device,
                            const SanitizationOptions *opts,
                            SanitizationResult *result);

/**
 * @brief Return a human-readable string for SsdSanitizeStatus.
 */
const char *ssd_sanitize_status_str(SsdSanitizeStatus status);

#endif /* ERASECURE_SSD_SANITIZER_H */
