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

/* ─── Encrypted volume type ──────────────────────────────────── */
typedef enum {
    ENCRYPTED_VOL_NONE             = 0,
    ENCRYPTED_VOL_SED_HARDWARE     = 1,   /* Opal / ATA / NVMe SED */
    ENCRYPTED_VOL_LUKS1            = 2,   /* Linux LUKS1 header */
    ENCRYPTED_VOL_LUKS2            = 3,   /* Linux LUKS2 header */
    ENCRYPTED_VOL_UNKNOWN          = 4,
} EncryptedVolumeType;

/**
 * @brief Query whether a device exposes self-encryption / key-management.
 *
 * Inspects device capabilities, ATA IDENTIFY, NVMe controller data,
 * and block headers.
 *
 * @param device  Device to query.
 * @return        KeyMgmtCapability code.
 */
KeyMgmtCapability key_mgmt_query_device(const StorageDevice *device);

/**
 * @brief Detect whether a block device or disk image contains a LUKS header.
 *
 * @param path      Path to device or image.
 * @param vol_type  Output: detected volume type (LUKS1, LUKS2, or NONE).
 * @return          ERASECURE_OK on success.
 */
ErasecureError key_mgmt_detect_luks(const char *path, EncryptedVolumeType *vol_type);

/**
 * @brief Securely zero out a buffer containing cryptographic key material.
 *
 * Uses OpenSSL's OPENSSL_cleanse() to ensure the compiler does not
 * optimize away the memory scrub.
 *
 * @param ptr  Pointer to memory to clean.
 * @param len  Number of bytes to zero.
 */
void key_mgmt_secure_cleanse(void *ptr, size_t len);

/**
 * @brief Return a human-readable string for a KeyMgmtCapability.
 */
const char *key_mgmt_capability_str(KeyMgmtCapability cap);

/**
 * @brief Return a human-readable string for an EncryptedVolumeType.
 */
const char *encrypted_volume_type_str(EncryptedVolumeType type);

#endif /* ERASECURE_KEY_MANAGEMENT_H */
