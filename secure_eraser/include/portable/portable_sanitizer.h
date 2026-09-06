/**
 * @file portable_sanitizer.h
 * @brief Portable / removable storage sanitization module.
 *
 * Handles:
 *   - USB HDD    → routes to HDD block erase logic
 *   - USB SSD    → routes to SSD module (with NAND caveat)
 *   - USB Flash  → block erase with NAND caveat
 *   - SD card    → block erase with NAND caveat
 *
 * The module inspects the underlying DeviceType to select the correct path,
 * NOT simply the transport type.  USB is an interface, not a storage medium.
 */
#ifndef ERASECURE_PORTABLE_SANITIZER_H
#define ERASECURE_PORTABLE_SANITIZER_H

#include "device/device.h"
#include "sanitization/sanitizer.h"
#include "common/error.h"

/**
 * @brief Check whether this module handles the device.
 * @return true for USB_HDD, USB_SSD, USB_FLASH, SD_CARD.
 */
bool portable_can_handle(const StorageDevice *device);

/**
 * @brief Check method support for portable storage.
 */
bool portable_supports_method(const StorageDevice *device, SanitizationMethod method);

/**
 * @brief Run sanitization on portable/removable storage.
 *
 * Routes to HDD sanitizer for USB HDDs, SSD sanitizer for USB SSDs,
 * and block erase for flash/SD card (test mode only).
 */
ErasecureError portable_sanitize(const StorageDevice *device,
                                 const SanitizationOptions *opts,
                                 SanitizationResult *result);

#endif /* ERASECURE_PORTABLE_SANITIZER_H */
