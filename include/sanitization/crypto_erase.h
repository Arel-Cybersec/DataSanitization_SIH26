/**
 * @file crypto_erase.h
 * @brief Cryptographic erase capability detection and execution stubs.
 *
 * IMPORTANT — What cryptographic erase IS and IS NOT:
 *
 *   Cryptographic erase means the destruction or invalidation of the
 *   encryption key(s) that protect data stored on a self-encrypting drive
 *   (SED).  When the key is destroyed, the ciphertext becomes
 *   cryptographically inaccessible without a brute-force attack.
 *
 *   Cryptographic erase is NOT:
 *     - Encrypting the disk with a new key.
 *     - Hashing disk contents.
 *     - Any operation that merely transforms data while leaving
 *       an accessible decryption key.
 *
 *   This module implements capability detection only.  Actual key
 *   destruction via ATA Security Erase (SECURITY ERASE UNIT enhanced) or
 *   NVMe Format NVM / Sanitize commands is NOT IMPLEMENTED in this
 *   version and will return CRYPTO_ERASE_NOT_IMPLEMENTED.
 */
#ifndef ERASECURE_CRYPTO_ERASE_H
#define ERASECURE_CRYPTO_ERASE_H

#include "device/device.h"
#include "common/error.h"

/* ─── Crypto erase status ────────────────────────────────────── */
typedef enum {
    CRYPTO_ERASE_SUPPORTED      = 0,
    CRYPTO_ERASE_UNSUPPORTED    = 1,   /* Device does not support SED/crypto erase */
    CRYPTO_ERASE_NOT_ENCRYPTED  = 2,   /* Device is not self-encrypting */
    CRYPTO_ERASE_NOT_IMPLEMENTED = 3,  /* Implementation not yet available */
    CRYPTO_ERASE_FAILED         = 4,
    CRYPTO_ERASE_SUCCESS        = 5,
} CryptoEraseStatus;

/**
 * @brief Query whether a device supports cryptographic erase.
 *
 * Inspects the device's reported capabilities.  Does NOT perform
 * any destructive operation.
 *
 * @param device  Device to query.
 * @return        CRYPTO_ERASE_SUPPORTED, CRYPTO_ERASE_UNSUPPORTED, or
 *                CRYPTO_ERASE_NOT_ENCRYPTED.
 */
CryptoEraseStatus crypto_erase_query(const StorageDevice *device);

/**
 * @brief Attempt cryptographic erase on a device.
 *
 * Currently returns CRYPTO_ERASE_NOT_IMPLEMENTED for all devices.
 * Future implementation requires:
 *   - For SATA SED: ATA SECURITY ERASE UNIT (enhanced) command.
 *   - For NVMe SED: NVMe Format NVM (ses=2) or Sanitize (action=2).
 *
 * @param device  Device to erase.
 * @return        CRYPTO_ERASE_NOT_IMPLEMENTED (current), or status on future impl.
 */
CryptoEraseStatus crypto_erase_execute(const StorageDevice *device);

/**
 * @brief Return a human-readable string for a CryptoEraseStatus.
 */
const char *crypto_erase_status_str(CryptoEraseStatus status);

#endif /* ERASECURE_CRYPTO_ERASE_H */
