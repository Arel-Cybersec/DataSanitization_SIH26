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

    /* Loop devices and ram disks are not real storage devices */
    if (strncmp(name, "loop", 4) == 0 || strncmp(name, "ram", 3) == 0) {
        return true; /* filter them out */
    }

    /* Check NVMe namespace whole disk vs partition:
     * Whole disk: nvme0n1, nvme1n1 (matches nvme\d+n\d+$)
     * Partition:  nvme0n1p1, nvme0n1p2 (contains 'p' after 'n') */
    if (strncmp(name, "nvme", 4) == 0) {
        const char *n_pos = strchr(name + 4, 'n');
        if (!n_pos) return false; /* unusual NVMe controller node */
        const char *p_pos = strchr(n_pos + 1, 'p');
        if (p_pos && *(p_pos + 1) >= '0' && *(p_pos + 1) <= '9') {
            return true; /* nvmeXnYpZ is a partition */
        }
        return false; /* nvmeXnY is a whole disk */
    }

    /* Check MMC / SD card whole disk vs partition:
     * Whole disk: mmcblk0, mmcblk1
     * Partition:  mmcblk0p1, mmcblk0p2 */
    if (strncmp(name, "mmcblk", 6) == 0) {
        const char *p_pos = strchr(name + 6, 'p');
        if (p_pos && *(p_pos + 1) >= '0' && *(p_pos + 1) <= '9') {
            return true; /* mmcblkXpY is a partition */
        }
        return false; /* mmcblkX is a whole disk */
    }

    /* SCSI / SATA / VirtIO / IDE disks:
     * Whole disk: sda, sdb, vda, hda (ends with non-digit)
     * Partition:  sda1, sdb2, vda1 (ends with digit) */
    char last = name[len - 1];
    if (last >= '0' && last <= '9') {
        return true; /* trailing digit on sd/hd/vd indicates a partition */
    }

    return false;
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

ErasecureError device_is_mounted(const char *device_path, bool *is_mounted)
{
    if (!device_path || !is_mounted) {
        return ERASECURE_ERR_INVALID_ARG;
    }

    *is_mounted = false;

    /* On non-Linux or systems without /proc/mounts, return OK with false */
    FILE *f = fopen(ERASECURE_PROC_MOUNTS, "r");
    if (!f) {
        /* Fall back to checking /etc/mtab */
        f = fopen("/etc/mtab", "r");
        if (!f) {
            return ERASECURE_OK;
        }
    }

    char line[1024];
    size_t dev_len = strlen(device_path);

    while (fgets(line, sizeof(line), f)) {
        /* Line format: <device> <mount_point> <fs_type> <options> <dump> <pass> */
        char mnt_dev[512];
        if (sscanf(line, "%511s", mnt_dev) != 1) {
            continue;
        }

        /* Direct match on device path (e.g., /dev/sda) */
        if (strcmp(mnt_dev, device_path) == 0) {
            *is_mounted = true;
            break;
        }

        /* Subpartition match: if device is /dev/sda, matches /dev/sda1, /dev/sda2...
         * or if device is /dev/nvme0n1, matches /dev/nvme0n1p1 */
        if (strncmp(mnt_dev, device_path, dev_len) == 0) {
            char next = mnt_dev[dev_len];
            if ((next >= '0' && next <= '9') || next == 'p') {
                *is_mounted = true;
                break;
            }
        }
    }

    fclose(f);
    return ERASECURE_OK;
}
