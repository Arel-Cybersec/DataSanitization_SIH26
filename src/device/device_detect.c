/**
 * @file device_detect.c
 * @brief Linux storage-device discovery via /sys/block.
 *
 * Walks /sys/block to enumerate whole-disk block devices.
 * Partitions (entries whose name contains digits after letters from
 * a parent name) are excluded.
 */
#define _POSIX_C_SOURCE 200809L

#include "device/device_detect.h"
#include "device/device_info.h"
#include "common/constants.h"
#include "common/error.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <stddef.h>
#include <stdbool.h>

/* ─── Helpers ────────────────────────────────────────────────── */

/**
 * @brief Return true if @p name looks like a partition rather than a whole disk.
 *
 * Heuristic:
 *   sda1, sdb2  → partition
 *   sda, sdb    → whole disk
 *   nvme0n1p1   → partition
 *   nvme0n1     → whole disk
 *   mmcblk0p1   → partition
 *   mmcblk0     → whole disk
 */
static bool is_partition(const char *name)
{
    if (!name || !*name) return false;

    size_t len = strlen(name);
    if (len == 0) return false;

    /* If the name ends in one or more digits AND contains a 'p' before
     * those digits (NVMe / MMC style), it's a partition. */
    size_t i = len;
    while (i > 0 && name[i - 1] >= '0' && name[i - 1] <= '9') {
        --i;
    }
    if (i == len) return false;  /* no trailing digits → not a partition */

    /* For SCSI/SATA disks (sda, sdb…) the partition has trailing digits
     * directly after the device letter(s); e.g., sda1.
     * For NVMe/MMC the separator is 'p': nvme0n1p1, mmcblk0p1. */
    if (i > 0 && name[i - 1] == 'p') {
        return true;   /* NVMe / MMC partition */
    }

    /* SCSI-style: trailing digit after non-digit characters */
    return true;
}

/* ─── Public API ─────────────────────────────────────────────── */

ErasecureError device_scan(StorageDevice *devices, size_t max_devices,
                           size_t *found)
{
    if (!devices || max_devices == 0 || !found) {
        return ERASECURE_ERR_INVALID_ARG;
    }

    *found = 0;

    DIR *dir = opendir(SYSFS_BLOCK_DIR);
    if (!dir) {
        /* /sys/block not available (not Linux or no access) */
        return ERASECURE_ERR_DEVICE_SCAN_FAIL;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL && *found < max_devices) {
        /* Skip . and .. */
        if (entry->d_name[0] == '.') continue;

        /* Skip loop devices */
        if (strncmp(entry->d_name, "loop", 4) == 0) continue;

        /* Skip partitions */
        if (is_partition(entry->d_name)) continue;

        /* Populate device info */
        StorageDevice *dev = &devices[*found];
        ErasecureError err = device_get_info(entry->d_name, dev);
        if (err == ERASECURE_OK) {
            (*found)++;
        }
        /* Non-fatal: skip unreadable entries */
    }

    closedir(dir);
    return ERASECURE_OK;
}

bool device_path_is_block_device(const char *path)
{
    if (!path) return false;

    /* Check against known block-device prefixes */
    static const char *prefixes[] = { ERASECURE_BLOCKDEV_PREFIXES };

    for (size_t i = 0; prefixes[i] != NULL; ++i) {
        if (strncmp(path, prefixes[i], strlen(prefixes[i])) == 0) {
            return true;
        }
    }

    /* Also check via stat: block special file */
    struct stat st;
    if (stat(path, &st) == 0) {
        if (S_ISBLK(st.st_mode)) {
            return true;
        }
    }

    return false;
}
