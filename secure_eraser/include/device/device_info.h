/**
 * @file device_info.h
 * @brief Detailed storage-device information retrieval.
 *
 * Reads sysfs attributes and ioctl results to populate a StorageDevice
 * struct for a given path.
 */
#ifndef ERASECURE_DEVICE_INFO_H
#define ERASECURE_DEVICE_INFO_H

#include "device/device.h"
#include "common/error.h"

/**
 * @brief Populate a StorageDevice from a block-device or sysfs entry.
 *
 * @param path    Block-device path (e.g., "/dev/sda") or bare name ("sda").
 * @param device  Output struct to populate.
 * @return        ERASECURE_OK on success.
 */
ErasecureError device_get_info(const char *path, StorageDevice *device);

/**
 * @brief Re-query capabilities for an already-populated StorageDevice.
 *
 * Call after initial discovery when a more detailed capability check
 * is needed (e.g., to detect ATA Secure Erase support).
 *
 * @param device  Device to update.
 * @return        ERASECURE_OK on success.
 */
ErasecureError device_refresh_capabilities(StorageDevice *device);

/**
 * @brief Derive DeviceType and TransportType from sysfs information.
 *
 * Uses rotational flag, subsystem symlink, and path prefix to
 * determine the underlying medium and interface.
 *
 * @param dev_name  Short device name (e.g., "sda", "nvme0n1").
 * @param device    Device struct to update (type, transport).
 */
void device_classify(const char *dev_name, StorageDevice *device);

#endif /* ERASECURE_DEVICE_INFO_H */
