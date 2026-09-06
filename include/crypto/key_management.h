/**
 * @file key_management.h
 * @brief Cryptographic key management and SED capability detection.
 *
 * Key management in EraseCure covers:
 *   1. Detecting whether a device is a self-encrypting drive (SED).
 *   2. Querying key-destruction capability.
 *   3. (Future) Issuing ATA/NVMe commands to destroy the data encryption key.
 *
 * We do NOT generate, store, or manage application-level encryption keys
 * for user data.  This module is strictly about hardware key destruction.
 */
#ifndef ERASECURE_KEY_MANAGEMENT_H
#define ERASECURE_KEY_MANAGEMENT_H

#include "device/device.h"
#include "common/error.h"

/* ─── SED capability result ──────────────────────────────────── */
typedef enum {
    KEY_MGMT_SED_DETECTED          = 0,
    KEY_MGMT_SED_NOT_DETECTED      = 1,
    KEY_MGMT_DETECTION_FAILED      = 2,
    KEY_MGMT_NOT_IMPLEMENTED       = 3,
} KeyMgmtCapability;

/**
 * @brief Query whether a device exposes self-encryption / key-management.
 *
 * For SATA devices, this would check ATA IDENTIFY DEVICE word 82 bit 1
 * (Security feature set) and related words.  Currently returns
 * KEY_MGMT_NOT_IMPLEMENTED until proper ioctl support is added.
 *
 * @param device  Device to query.
 * @return        KeyMgmtCapability code.
 */
KeyMgmtCapability key_mgmt_query_device(const StorageDevice *device);

/**
 * @brief Return a human-readable string for a KeyMgmtCapability.
 */
const char *key_mgmt_capability_str(KeyMgmtCapability cap);

#endif /* ERASECURE_KEY_MANAGEMENT_H */
