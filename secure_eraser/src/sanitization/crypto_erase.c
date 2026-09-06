/**
 * @file crypto_erase.c
 * @brief Cryptographic erase capability query and execution (stub).
 */
#include "sanitization/crypto_erase.h"
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

    /*
     * STUB — NOT IMPLEMENTED
     *
     * Cryptographic erase requires hardware-level key destruction:
     *
     *   SATA SED:  ATA SECURITY ERASE UNIT (enhanced mode, bit 1 set).
     *              Requires: SG_IO ioctl with ATA pass-through, device
     *              must be in "security enabled" state, correct password.
     *
     *   NVMe SED:  Format NVM command (ses=2, Cryptographic Erase) or
     *              Sanitize command (SANACT=0x4, Block Erase).
     *              Requires: NVMe admin passthru ioctl (NVME_IOCTL_ADMIN_CMD).
     *
     * These ioctls require root privileges and real hardware.
     * Implementation will be added in a future phase after extensive
     * safety testing on dedicated test hardware.
     *
     * IMPORTANT: This function must NEVER be implemented as simply
     * overwriting data with a new key or hash.  That is NOT crypto erase.
     */
    (void)device;
    return CRYPTO_ERASE_NOT_IMPLEMENTED;
}
