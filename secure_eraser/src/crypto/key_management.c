/**
 * @file key_management.c
 * @brief SED capability detection (stubs pending ioctl implementation).
 */
#include "crypto/key_management.h"
#include "device/device.h"

const char *key_mgmt_capability_str(KeyMgmtCapability cap)
{
    switch (cap) {
        case KEY_MGMT_SED_DETECTED:     return "Self-encrypting drive detected";
        case KEY_MGMT_SED_NOT_DETECTED: return "No self-encryption detected";
        case KEY_MGMT_DETECTION_FAILED: return "Detection failed";
        case KEY_MGMT_NOT_IMPLEMENTED:  return "Detection not implemented";
        default:                        return "Unknown";
    }
}

KeyMgmtCapability key_mgmt_query_device(const StorageDevice *device)
{
    if (!device) return KEY_MGMT_DETECTION_FAILED;

    /*
     * STUB: Real implementation would:
     *   For SATA: issue ATA IDENTIFY DEVICE (ioctl HDIO_GET_IDENTITY or SG_IO)
     *             and check Security feature set bits (word 82 bit 1,
     *             word 128 for security status).
     *   For NVMe: read Identify Controller (byte 256 FGUID / byte 265 SCC)
     *             or check Namespace data for FDP / crypto capabilities.
     *
     * Until that ioctl layer is implemented, we return NOT_IMPLEMENTED.
     */
    (void)device;
    return KEY_MGMT_NOT_IMPLEMENTED;
}
