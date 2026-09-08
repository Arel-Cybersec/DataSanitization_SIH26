/**
 * @file device.h
 * @brief StorageDevice structure and associated enumerations.
 *
 * This is the central device abstraction.  All sanitizers operate on
 * StorageDevice objects; none require knowledge of the physical transport
 * or hardware specifics beyond what is captured here.
 */
#ifndef ERASECURE_DEVICE_H
#define ERASECURE_DEVICE_H

#include "common/types.h"
#include "common/constants.h"
#include "common/error.h"
#include <stdint.h>
#include <stdbool.h>

/* ─── Device type ────────────────────────────────────────────── */
typedef enum {
    DEVICE_TYPE_UNKNOWN     = 0,
    DEVICE_TYPE_HDD         = 1,   /* Rotational hard disk */
    DEVICE_TYPE_SATA_SSD    = 2,   /* SATA solid-state drive */
    DEVICE_TYPE_NVME_SSD    = 3,   /* NVMe solid-state drive */
    DEVICE_TYPE_USB_HDD     = 4,   /* USB-attached rotational disk */
    DEVICE_TYPE_USB_SSD     = 5,   /* USB-attached SSD */
    DEVICE_TYPE_USB_FLASH   = 6,   /* USB flash storage (NAND, no rotation) */
    DEVICE_TYPE_SD_CARD     = 7,   /* SD / microSD / MMC card */
} DeviceType;

/* ─── Interface / transport ──────────────────────────────────── */
typedef enum {
    TRANSPORT_UNKNOWN = 0,
    TRANSPORT_SATA    = 1,
    TRANSPORT_NVME    = 2,
    TRANSPORT_USB     = 3,
    TRANSPORT_SD      = 4,
} TransportType;

/* ─── Sanitization methods ───────────────────────────────────── */
typedef enum {
    SANITIZE_METHOD_NONE            = 0,
    SANITIZE_METHOD_BLOCK_ERASE     = 1,  /* Pattern overwrite of logical blocks */
    SANITIZE_METHOD_CRYPTO_ERASE    = 2,  /* Key destruction (hardware-assisted) */
    SANITIZE_METHOD_DEVICE_NATIVE   = 3,  /* ATA Secure Erase / NVMe Sanitize */
} SanitizationMethod;

/* ─── Detected device capabilities ──────────────────────────── */
typedef struct {
    bool supports_block_erase;      /* Always true for writable block devices */
    bool supports_crypto_erase;     /* True only if hardware SED is detected */
    bool supports_device_native;    /* ATA Secure Erase / NVMe Sanitize available */
    bool is_self_encrypting;        /* Device reports SED capability */
    bool ata_secure_erase_supported;
    bool ata_enhanced_erase_supported;
    bool nvme_sanitize_supported;
    bool nvme_format_supported;
} DeviceCapabilities;

/* ─── Encryption status ──────────────────────────────────────── */
typedef enum {
    ENCRYPTION_STATUS_UNKNOWN       = 0,
    ENCRYPTION_STATUS_NOT_ENCRYPTED = 1,
    ENCRYPTION_STATUS_ENCRYPTED     = 2,   /* SED / hardware encryption active */
    ENCRYPTION_STATUS_LOCKED        = 3,
} EncryptionStatus;

/* ─── Central storage device record ─────────────────────────── */
struct StorageDevice {
    /* Identity */
    ErasecureId        device_id;               /* Internal UUID */
    char               path[ERASECURE_MAX_PATH_LEN];
    char               model[ERASECURE_MAX_MODEL_LEN];
    char               serial[ERASECURE_MAX_SERIAL_LEN];

    /* Geometry */
    uint64_t           capacity_bytes;
    uint32_t           logical_sector_size;
    uint32_t           physical_sector_size;

    /* Classification */
    DeviceType         device_type;
    TransportType      transport_type;

    /* Flags */
    bool               is_removable;
    bool               is_read_only;
    bool               is_rotational;          /* false = SSD/flash */

    /* Encryption */
    EncryptionStatus   encryption_status;

    /* Capabilities (populated by device_refresh_capabilities) */
    DeviceCapabilities capabilities;
};

/**
 * @brief Initialise a StorageDevice to safe defaults.
 * @param dev  Pointer to device to initialise (must not be NULL).
 */
void device_init(StorageDevice *dev);

/**
 * @brief Return a display string for a DeviceType.
 */
const char *device_type_str(DeviceType type);

/**
 * @brief Return a display string for a TransportType.
 */
const char *device_transport_str(TransportType transport);

/**
 * @brief Return a display string for a SanitizationMethod.
 */
const char *sanitization_method_str(SanitizationMethod method);

/**
 * @brief Print a human-readable summary of a StorageDevice to stdout.
 */
void device_print_info(const StorageDevice *dev);

#endif /* ERASECURE_DEVICE_H */
