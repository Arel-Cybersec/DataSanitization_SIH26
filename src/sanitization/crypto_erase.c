/**
 * @file crypto_erase.c
 * @brief Cryptographic erase capability query and execution (stub).
 */
#include "sanitization/crypto_erase.h"
#include "crypto/key_management.h"
#include "device/device.h"

const char *crypto_erase_status_str(CryptoEraseStatus status)
{
    switch (status) {
        case CRYPTO_ERASE_SUPPORTED:       return "Supported";
        case CRYPTO_ERASE_UNSUPPORTED:     return "Unsupported";
        case CRYPTO_ERASE_NOT_ENCRYPTED:   return "Device is not self-encrypting";
        case CRYPTO_ERASE_NOT_IMPLEMENTED: return "Not implemented in this version";
        case CRYPTO_ERASE_FAILED:          return "Failed";
        case CRYPTO_ERASE_SUCCESS:         return "Success";
        default:                           return "Unknown";
    }
}

CryptoEraseStatus crypto_erase_query(const StorageDevice *device)
{
    if (!device) return CRYPTO_ERASE_UNSUPPORTED;

    if (device->capabilities.supports_crypto_erase) {
        return CRYPTO_ERASE_SUPPORTED;
    }

    if (device->encryption_status == ENCRYPTION_STATUS_NOT_ENCRYPTED ||
        device->encryption_status == ENCRYPTION_STATUS_UNKNOWN) {
        return CRYPTO_ERASE_NOT_ENCRYPTED;
    }

    return CRYPTO_ERASE_UNSUPPORTED;
}

CryptoEraseStatus crypto_erase_execute(const StorageDevice *device)
{
    if (!device) return CRYPTO_ERASE_FAILED;

    /* First, check reported device encryption capabilities */
    CryptoEraseStatus query_status = crypto_erase_query(device);
    if (query_status == CRYPTO_ERASE_NOT_ENCRYPTED) {
        return CRYPTO_ERASE_NOT_ENCRYPTED;
    }
    if (query_status == CRYPTO_ERASE_UNSUPPORTED) {
        return CRYPTO_ERASE_UNSUPPORTED;
    }

    /*
     * Cryptographic erase requires hardware-level key destruction:
     *   SATA SED:  ATA SANITIZE (Crypto Scramble) or ATA SECURITY ERASE UNIT (enhanced).
     *   NVMe SED:  NVMe Sanitize (Crypto Erase, SANACT=0x4) or Format NVM (SES=2).
     *
     * These commands destroy internal media encryption keys in the drive controller.
     * When hardware pass-through is active on Linux with root privileges:
     */
#ifdef __linux__
    if (device->transport_type == TRANSPORT_NVME &&
        device->capabilities.supports_crypto_erase) {
        /* NVMe sanitize crypto erase architecture prepared */
        return CRYPTO_ERASE_NOT_IMPLEMENTED;
    } else if (device->transport_type == TRANSPORT_SATA &&
               device->capabilities.supports_crypto_erase) {
        /* ATA sanitize crypto scramble architecture prepared */
        return CRYPTO_ERASE_NOT_IMPLEMENTED;
    }
#endif

    return CRYPTO_ERASE_NOT_IMPLEMENTED;
}

CryptoEraseStatus crypto_erase_synthetic_key(uint8_t *key_buf, size_t key_len)
{
    if (!key_buf || key_len == 0) {
        return CRYPTO_ERASE_FAILED;
    }

    /* Securely wipe key material using OpenSSL cleanse (immune to compiler optimization) */
    key_mgmt_secure_cleanse(key_buf, key_len);

    /* Verify memory was zeroed */
    for (size_t i = 0; i < key_len; ++i) {
        if (key_buf[i] != 0) {
            return CRYPTO_ERASE_FAILED;
        }
    }

    return CRYPTO_ERASE_SUCCESS;
}
