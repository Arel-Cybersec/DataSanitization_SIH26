/**
 * @file device_info.c
 * @brief Populate StorageDevice from sysfs attributes.
 */
#define _POSIX_C_SOURCE 200809L

#include "device/device_info.h"
#include "device/device.h"
#include "common/constants.h"
#include "common/error.h"
#include "ata/ata_sanitize.h"
#include "nvme/nvme_sanitize.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <unistd.h>
#include <limits.h>

/* ─── sysfs read helpers ─────────────────────────────────────── */

/**
 * @brief Read a single line from a sysfs file into buf (strips newline).
 * @return 0 on success, -1 on failure.
 */
static int sysfs_read_str(const char *path, char *buf, size_t buf_len)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char *res = fgets(buf, (int)buf_len, f);
    fclose(f);

    if (!res) return -1;

    /* Strip trailing whitespace/newline */
    size_t len = strlen(buf);
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r' ||
                       buf[len - 1] == ' ')) {
        buf[--len] = '\0';
    }
    return 0;
}

static int sysfs_read_uint64(const char *path, uint64_t *out)
{
    char buf[32];
    if (sysfs_read_str(path, buf, sizeof(buf)) != 0) return -1;
    char *end;
    unsigned long long v = strtoull(buf, &end, 10);
    if (end == buf) return -1;
    *out = (uint64_t)v;
    return 0;
}

static int sysfs_read_uint32(const char *path, uint32_t *out)
{
    uint64_t v;
    if (sysfs_read_uint64(path, &v) != 0) return -1;
    *out = (uint32_t)v;
    return 0;
}

/* ─── Device classification ──────────────────────────────────── */

void device_classify(const char *dev_name, StorageDevice *device)
{
    if (!dev_name || !device) return;

    /* NVMe: name starts with "nvme" */
    if (strncmp(dev_name, "nvme", 4) == 0) {
        device->transport_type = TRANSPORT_NVME;
        device->device_type    = DEVICE_TYPE_NVME_SSD;
        device->is_rotational  = false;
        return;
    }

    /* SD / MMC: name starts with "mmcblk" */
    if (strncmp(dev_name, "mmcblk", 6) == 0) {
        device->transport_type = TRANSPORT_SD;
        device->device_type    = DEVICE_TYPE_SD_CARD;
        device->is_rotational  = false;
        return;
    }

    /* Check sysfs subsystem symlink to detect USB */
    char subsystem_path[ERASECURE_MAX_SYSFS_PATH_LEN];
    char subsystem_target[ERASECURE_MAX_SYSFS_PATH_LEN];

    int n = snprintf(subsystem_path, sizeof(subsystem_path),
                     SYSFS_SUBSYSTEM_FMT, dev_name);
    if (n > 0 && (size_t)n < sizeof(subsystem_path)) {
        ssize_t sym_len = readlink(subsystem_path,
                                   subsystem_target,
                                   sizeof(subsystem_target) - 1);
        if (sym_len > 0) {
            subsystem_target[sym_len] = '\0';
            if (strstr(subsystem_target, "usb")) {
                device->transport_type = TRANSPORT_USB;
                /* Determine underlying medium from rotational flag */
                if (device->is_rotational) {
                    device->device_type = DEVICE_TYPE_USB_HDD;
                } else {
                    /* Cannot reliably distinguish USB SSD from USB flash
                     * without querying vendor-specific data.  Default to flash. */
                    device->device_type = DEVICE_TYPE_USB_FLASH;
                }
                return;
            }
        }
    }

    /* SATA / generic block device */
    device->transport_type = TRANSPORT_SATA;
    if (device->is_rotational) {
        device->device_type = DEVICE_TYPE_HDD;
    } else {
        device->device_type = DEVICE_TYPE_SATA_SSD;
    }
}

/* ─── Public API ─────────────────────────────────────────────── */

ErasecureError device_get_info(const char *path, StorageDevice *device)
{
    if (!path || !device) return ERASECURE_ERR_INVALID_ARG;

    device_init(device);

    /* Determine short device name (strip "/dev/" prefix if present) */
    const char *dev_name = path;
    if (strncmp(path, "/dev/", 5) == 0) {
        dev_name = path + 5;
        /* Store full path */
        snprintf(device->path, sizeof(device->path), "%s", path);
    } else {
        /* Assume bare sysfs name; build /dev/ path */
        snprintf(device->path, sizeof(device->path), "/dev/%s", dev_name);
    }

    char sysfs[ERASECURE_MAX_SYSFS_PATH_LEN];
    uint64_t tmp64;
    uint32_t tmp32;
    char tmpstr[ERASECURE_MAX_MODEL_LEN];

    /* ── Rotational ── */
    snprintf(sysfs, sizeof(sysfs), SYSFS_ROTATIONAL_FMT, dev_name);
    if (sysfs_read_uint32(sysfs, &tmp32) == 0) {
        device->is_rotational = (tmp32 != 0);
    }

    /* ── Removable ── */
    snprintf(sysfs, sizeof(sysfs), SYSFS_REMOVABLE_FMT, dev_name);
    if (sysfs_read_uint32(sysfs, &tmp32) == 0) {
        device->is_removable = (tmp32 != 0);
    }

    /* ── Read-only ── */
    snprintf(sysfs, sizeof(sysfs), SYSFS_RO_FMT, dev_name);
    if (sysfs_read_uint32(sysfs, &tmp32) == 0) {
        device->is_read_only = (tmp32 != 0);
    }

    /* ── Capacity (sysfs reports 512-byte sectors) ── */
    snprintf(sysfs, sizeof(sysfs), SYSFS_SIZE_FMT, dev_name);
    if (sysfs_read_uint64(sysfs, &tmp64) == 0) {
        device->capacity_bytes = tmp64 * 512ULL;
    }

    /* ── Logical block size ── */
    snprintf(sysfs, sizeof(sysfs), SYSFS_LOGICAL_BS_FMT, dev_name);
    if (sysfs_read_uint32(sysfs, &tmp32) == 0 && tmp32 >= 512U) {
        device->logical_sector_size = tmp32;
    }

    /* ── Physical block size ── */
    snprintf(sysfs, sizeof(sysfs), SYSFS_PHYSICAL_BS_FMT, dev_name);
    if (sysfs_read_uint32(sysfs, &tmp32) == 0 && tmp32 >= 512U) {
        device->physical_sector_size = tmp32;
    }

    /* ── Model ── */
    snprintf(sysfs, sizeof(sysfs), SYSFS_MODEL_FMT, dev_name);
    if (sysfs_read_str(sysfs, tmpstr, sizeof(tmpstr)) == 0) {
        snprintf(device->model, sizeof(device->model), "%s", tmpstr);
    }

    /* ── Serial ── */
    snprintf(sysfs, sizeof(sysfs), SYSFS_SERIAL_FMT, dev_name);
    if (sysfs_read_str(sysfs, tmpstr, sizeof(tmpstr)) == 0) {
        snprintf(device->serial, sizeof(device->serial), "%s", tmpstr);
    }

    /* ── Classification ── */
    device_classify(dev_name, device);

    /* Ensure device_id is populated */
    if (device->device_id[0] == '\0') {
        snprintf(device->device_id, sizeof(device->device_id),
                 "dev-%s", dev_name);
    }

    /* ── Default capabilities ── */
    device->capabilities.supports_block_erase = !device->is_read_only;

    return ERASECURE_OK;
}

ErasecureError device_refresh_capabilities(StorageDevice *device)
{
    if (!device) return ERASECURE_ERR_INVALID_ARG;

    /* Re-check read-only status */
    const char *dev_name = device->path;
    if (strncmp(dev_name, "/dev/", 5) == 0) dev_name += 5;

    char sysfs[ERASECURE_MAX_SYSFS_PATH_LEN];
    uint32_t tmp32;

    snprintf(sysfs, sizeof(sysfs), SYSFS_RO_FMT, dev_name);
    if (sysfs_read_uint32(sysfs, &tmp32) == 0) {
        device->is_read_only = (tmp32 != 0);
    }

    device->capabilities.supports_block_erase = !device->is_read_only;

#ifdef __linux__
    if (device->transport_type == TRANSPORT_SATA ||
        device->device_type == DEVICE_TYPE_HDD ||
        device->device_type == DEVICE_TYPE_SATA_SSD) {
        AtaSanitizeCapabilities ata_caps;
        if (ata_sanitize_query(device->path, &ata_caps) == ERASECURE_OK) {
            device->capabilities.ata_secure_erase_supported = ata_caps.can_security_erase;
            device->capabilities.ata_enhanced_erase_supported = ata_caps.can_enhanced_erase;
            device->capabilities.supports_device_native =
                ata_caps.can_security_erase ||
                ata_caps.can_sanitize_block_erase ||
                ata_caps.can_sanitize_overwrite;
            device->capabilities.supports_crypto_erase = ata_caps.can_sanitize_crypto;
            device->capabilities.is_self_encrypting = ata_caps.can_sanitize_crypto;
            if (ata_caps.can_sanitize_crypto) {
                device->encryption_status = ENCRYPTION_STATUS_ENCRYPTED;
            }
        }
    } else if (device->transport_type == TRANSPORT_NVME ||
               device->device_type == DEVICE_TYPE_NVME_SSD) {
        NvmeSanitizeCapabilities nvme_caps;
        if (nvme_sanitize_query(device->path, &nvme_caps) == ERASECURE_OK) {
            device->capabilities.nvme_sanitize_supported =
                nvme_caps.can_sanitize_block ||
                nvme_caps.can_sanitize_overwrite ||
                nvme_caps.can_sanitize_crypto;
            device->capabilities.nvme_format_supported = nvme_caps.can_format_nvm;
            device->capabilities.supports_device_native =
                device->capabilities.nvme_sanitize_supported ||
                nvme_caps.can_format_nvm;
            device->capabilities.supports_crypto_erase =
                nvme_caps.can_format_crypto_erase ||
                nvme_caps.can_sanitize_crypto;
            device->capabilities.is_self_encrypting = device->capabilities.supports_crypto_erase;
            if (device->capabilities.supports_crypto_erase) {
                device->encryption_status = ENCRYPTION_STATUS_ENCRYPTED;
            }
        }
    }
#else
    device->capabilities.supports_crypto_erase = false;
    device->capabilities.supports_device_native = false;
#endif

    return ERASECURE_OK;
}

ErasecureError device_get_capabilities(const StorageDevice *device, DeviceCapabilities *caps)
{
    if (!device || !caps) return ERASECURE_ERR_INVALID_ARG;
    *caps = device->capabilities;
    return ERASECURE_OK;
}
