/**
 * @file hdd_sanitizer.h
 * @brief HDD-specific sanitization module.
 *
 * STATUS of real-device operations:
 *   - ATA Secure Erase (SECURITY ERASE UNIT): NOT IMPLEMENTED (stub).
 *   - ATA Enhanced Secure Erase:              NOT IMPLEMENTED (stub).
 *   - Block overwrite on test images:         IMPLEMENTED.
 *
 * Do NOT claim that block overwrite is equivalent to ATA Secure Erase
 * or any government-grade data destruction standard.
 */
#ifndef ERASECURE_HDD_SANITIZER_H
#define ERASECURE_HDD_SANITIZER_H

#include "device/device.h"
#include "sanitization/sanitizer.h"
#include "common/error.h"

/* ─── HDD-specific sanitization result codes ─────────────────── */
typedef enum {
    HDD_SANITIZE_SUCCESS         = 0,
    HDD_SANITIZE_UNSUPPORTED     = 1,
    HDD_SANITIZE_NOT_IMPLEMENTED = 2,
    HDD_SANITIZE_FAILED          = 3,
    HDD_SANITIZE_DEVICE_ERROR    = 4,
    HDD_SANITIZE_SAFETY_BLOCKED  = 5,
} HddSanitizeStatus;

/**
 * @brief Check whether this module can handle the device.
 * @return true if device_type is HDD or USB_HDD.
 */
bool hdd_can_handle(const StorageDevice *device);

/**
 * @brief Check whether the device supports a specific sanitization method.
 */
bool hdd_supports_method(const StorageDevice *device, SanitizationMethod method);

/**
 * @brief Run HDD sanitization.
 *
 * In test mode (opts->test_mode), routes to block_erase_image() on the
 * file path stored in device->path.
 *
 * For real devices: returns HDD_SANITIZE_NOT_IMPLEMENTED until
 * ATA Secure Erase via SG_IO / hdparm protocol is implemented.
 *
 * @param device  Device to sanitize.
 * @param opts    Sanitization options.
 * @param result  Output result.
 * @return        ERASECURE_OK if operation ran (check result codes),
 *                ERASECURE_ERR_* on dispatch failure.
 */
ErasecureError hdd_sanitize(const StorageDevice *device,
                            const SanitizationOptions *opts,
                            SanitizationResult *result);

/**
 * @brief Return a human-readable string for HddSanitizeStatus.
 */
const char *hdd_sanitize_status_str(HddSanitizeStatus status);

#endif /* ERASECURE_HDD_SANITIZER_H */
