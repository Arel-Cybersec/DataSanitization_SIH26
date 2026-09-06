/**
 * @file device_detect.h
 * @brief Linux storage-device discovery API.
 *
 * Discovers block devices via /sys/block without shelling out to
 * external commands.  Partition devices (e.g., sda1) are excluded.
 */
#ifndef ERASECURE_DEVICE_DETECT_H
#define ERASECURE_DEVICE_DETECT_H

#include "device/device.h"
#include "common/error.h"
#include <stddef.h>

/**
 * @brief Enumerate all top-level storage devices visible in /sys/block.
 *
 * Fills up to @p max_devices entries in @p devices.  Partition sub-devices
 * are skipped.  Caller must provide a buffer of at least @p max_devices
 * StorageDevice structs.
 *
 * @param devices      Output array of StorageDevice (caller-allocated).
 * @param max_devices  Maximum number of entries to fill.
 * @param found        Set to the number of devices actually found.
 * @return             ERASECURE_OK on success, error code otherwise.
 */
ErasecureError device_scan(StorageDevice *devices, size_t max_devices,
                           size_t *found);

/**
 * @brief Check whether a string looks like a physical block-device path.
 *
 * Used by sanitization modules to prevent test-mode functions from
 * accidentally operating on real devices.
 *
 * @param path  Path to check.
 * @return      true if the path matches a known block-device prefix.
 */
bool device_path_is_block_device(const char *path);

#endif /* ERASECURE_DEVICE_DETECT_H */
