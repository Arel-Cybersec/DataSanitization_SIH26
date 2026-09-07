#include "crypto/key_management.h"
#include "device/device.h"
#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>

const char *key_mgmt_capability_str(KeyMgmtCapability cap)
{
    switch (cap) {
        case KEY_MGMT_SED_DETECTED:     return "Self-encrypting drive / encrypted volume detected";
        case KEY_MGMT_SED_NOT_DETECTED: return "No self-encryption or LUKS volume detected";
        case KEY_MGMT_DETECTION_FAILED: return "Detection failed";
        case KEY_MGMT_NOT_IMPLEMENTED:  return "Detection not implemented";
        default:                        return "Unknown";
    }
}

const char *encrypted_volume_type_str(EncryptedVolumeType type)
{
    switch (type) {
        case ENCRYPTED_VOL_NONE:         return "Not encrypted";
        case ENCRYPTED_VOL_SED_HARDWARE: return "Hardware SED (ATA/NVMe Opal)";
        case ENCRYPTED_VOL_LUKS1:        return "Linux LUKS1 volume";
        case ENCRYPTED_VOL_LUKS2:        return "Linux LUKS2 volume";
        default:                         return "Unknown encryption type";
    }
}

void key_mgmt_secure_cleanse(void *ptr, size_t len)
{
    if (!ptr || len == 0) return;
    OPENSSL_cleanse(ptr, len);
}

ErasecureError key_mgmt_detect_luks(const char *path, EncryptedVolumeType *vol_type)
{
    if (!path || !vol_type) return ERASECURE_ERR_INVALID_ARG;
    *vol_type = ENCRYPTED_VOL_NONE;

    FILE *f = fopen(path, "rb");
    if (!f) return ERASECURE_ERR_OPEN_FAILED;

    /* LUKS header magic: 'L', 'U', 'K', 'S', 0xba, 0xbe (6 bytes) */
    uint8_t hdr[16];
    size_t n = fread(hdr, 1, sizeof(hdr), f);
    fclose(f);

    if (n < 8) return ERASECURE_OK;

    static const uint8_t luks_magic[6] = { 'L', 'U', 'K', 'S', 0xba, 0xbe };
    if (memcmp(hdr, luks_magic, 6) == 0) {
        uint16_t ver = (uint16_t)((hdr[6] << 8) | hdr[7]);
        if (ver == 1) {
            *vol_type = ENCRYPTED_VOL_LUKS1;
        } else if (ver == 2) {
            *vol_type = ENCRYPTED_VOL_LUKS2;
        } else {
            *vol_type = ENCRYPTED_VOL_UNKNOWN;
        }
    }

    return ERASECURE_OK;
}

KeyMgmtCapability key_mgmt_query_device(const StorageDevice *device)
{
    if (!device) return KEY_MGMT_DETECTION_FAILED;

    /* Check if hardware SED was detected during device discovery */
    if (device->capabilities.supports_crypto_erase ||
        device->capabilities.is_self_encrypting ||
        device->encryption_status == ENCRYPTION_STATUS_ENCRYPTED) {
        return KEY_MGMT_SED_DETECTED;
    }

    /* Check if device path contains a LUKS encrypted volume header */
    if (device->path[0] != '\0') {
        EncryptedVolumeType vol_type = ENCRYPTED_VOL_NONE;
        if (key_mgmt_detect_luks(device->path, &vol_type) == ERASECURE_OK &&
            vol_type != ENCRYPTED_VOL_NONE) {
            return KEY_MGMT_SED_DETECTED;
        }
    }

    return KEY_MGMT_SED_NOT_DETECTED;
}
