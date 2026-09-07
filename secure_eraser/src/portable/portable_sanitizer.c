/**
 * @file portable_sanitizer.c
 * @brief Portable/removable storage sanitization routing.
 */
#include "portable/portable_sanitizer.h"
#include "hdd/hdd_sanitizer.h"
#include "ssd/ssd_sanitizer.h"
#include "sanitization/block_erase.h"
#include "sanitization/verification.h"
#include "common/error.h"

#include <string.h>
#include <stdio.h>

bool portable_can_handle(const StorageDevice *device)
{
    if (!device) return false;
    switch (device->device_type) {
        case DEVICE_TYPE_USB_HDD:
        case DEVICE_TYPE_USB_SSD:
        case DEVICE_TYPE_USB_FLASH:
        case DEVICE_TYPE_SD_CARD:
            return true;
        default:
            return false;
    }
}

bool portable_supports_method(const StorageDevice *device, SanitizationMethod method)
{
    if (!device) return false;
    if (method == SANITIZE_METHOD_BLOCK_ERASE) {
        return !device->is_read_only;
    }
    return false;
}

ErasecureError portable_sanitize(const StorageDevice *device,
                                 const SanitizationOptions *opts,
                                 SanitizationResult *result)
{
    if (!device || !opts || !result) return ERASECURE_ERR_INVALID_ARG;

    result->method_used = opts->method;

    switch (device->device_type) {
        case DEVICE_TYPE_USB_HDD:
            /* Route to HDD sanitizer (same underlying medium) */
            return hdd_sanitize(device, opts, result);

        case DEVICE_TYPE_USB_SSD:
            /* Route to SSD sanitizer (same underlying medium) */
            return ssd_sanitize(device, opts, result);

        case DEVICE_TYPE_USB_FLASH:
        case DEVICE_TYPE_SD_CARD:
            /* Flash/SD: only block erase supported in test mode.
             * NOTE: NAND erasure not guaranteed by logical overwrite. */
            if (opts->method != SANITIZE_METHOD_BLOCK_ERASE) {
                result->result_code = ERASECURE_ERR_UNSUPPORTED;
                snprintf(result->error_message, sizeof(result->error_message),
                         "Only block erase is supported for USB Flash / SD cards.");
                return ERASECURE_ERR_UNSUPPORTED;
            }
            if (!opts->test_mode) {
                BlockEraseOptions be_opts = opts->block_erase;
                be_opts.progress_cb = opts->progress_cb;
                be_opts.user_data   = opts->user_data;
                ErasecureError ret = block_erase_device(device, &be_opts,
                                                        device->path,
                                                        &result->block_result);
                result->result_code = ret;
                snprintf(result->verify_result.confidence_note,
                         sizeof(result->verify_result.confidence_note),
                         "CAVEAT: Logical block overwrite on USB Flash/SD card "
                         "cannot guarantee physical NAND erasure.");
                return ret;
            }
            {
                BlockEraseOptions be_opts = opts->block_erase;
                be_opts.progress_cb = opts->progress_cb;
                be_opts.user_data   = opts->user_data;
                ErasecureError ret = block_erase_image(device->path, &be_opts,
                                                       &result->block_result);
                result->result_code = ret;
                if (ret == ERASECURE_OK && be_opts.verify_mode != VERIFY_NONE) {
                    verify_image_pattern(device->path, be_opts.pattern,
                                         be_opts.block_size, be_opts.verify_mode,
                                         &result->verify_result);
                }
                return ret;
            }

        default:
            result->result_code = ERASECURE_ERR_UNSUPPORTED;
            return ERASECURE_ERR_UNSUPPORTED;
    }
}
