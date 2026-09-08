/**
 * @file hdd_sanitizer.c
 * @brief HDD sanitization implementation.
 */
#include "hdd/hdd_sanitizer.h"
#include "sanitization/block_erase.h"
#include "sanitization/verification.h"
#include "common/error.h"

#include <string.h>
#include <stdio.h>

const char *hdd_sanitize_status_str(HddSanitizeStatus status)
{
    switch (status) {
        case HDD_SANITIZE_SUCCESS:          return "Success";
        case HDD_SANITIZE_UNSUPPORTED:      return "Unsupported";
        case HDD_SANITIZE_NOT_IMPLEMENTED:  return "Not implemented";
        case HDD_SANITIZE_FAILED:           return "Failed";
        case HDD_SANITIZE_DEVICE_ERROR:     return "Device error";
        case HDD_SANITIZE_SAFETY_BLOCKED:   return "Safety blocked";
        default:                            return "Unknown";
    }
}

bool hdd_can_handle(const StorageDevice *device)
{
    if (!device) return false;
    return (device->device_type == DEVICE_TYPE_HDD ||
            device->device_type == DEVICE_TYPE_USB_HDD);
}

bool hdd_supports_method(const StorageDevice *device, SanitizationMethod method)
{
    if (!device) return false;
    switch (method) {
        case SANITIZE_METHOD_BLOCK_ERASE:
            return !device->is_read_only;
        case SANITIZE_METHOD_CRYPTO_ERASE:
            return device->capabilities.supports_crypto_erase;
        case SANITIZE_METHOD_DEVICE_NATIVE:
            /* ATA Secure Erase — NOT implemented yet */
            return false;
        default:
            return false;
    }
}

ErasecureError hdd_sanitize(const StorageDevice *device,
                            const SanitizationOptions *opts,
                            SanitizationResult *result)
{
    if (!device || !opts || !result) return ERASECURE_ERR_INVALID_ARG;

    result->method_used = opts->method;

    switch (opts->method) {
        case SANITIZE_METHOD_BLOCK_ERASE:
            if (!opts->test_mode) {
                /* Real physical HDD block erase with explicit confirmation */
                BlockEraseOptions be_opts = opts->block_erase;
                be_opts.progress_cb = opts->progress_cb;
                be_opts.user_data   = opts->user_data;

                ErasecureError ret = block_erase_device(device, &be_opts,
                                                        device->path,
                                                        &result->block_result);
                result->result_code = ret;
                if (ret != ERASECURE_OK) {
                    snprintf(result->error_message, sizeof(result->error_message),
                             "%s", result->block_result.error_message);
                }
                return ret;
            }
            /* Test-image mode: delegate to block_erase_image */
            {
                BlockEraseOptions be_opts = opts->block_erase;
                be_opts.progress_cb = opts->progress_cb;
                be_opts.user_data   = opts->user_data;

                ErasecureError ret = block_erase_image(device->path, &be_opts,
                                                       &result->block_result);
                result->result_code = ret;

                /* Run verification if requested */
                if (ret == ERASECURE_OK &&
                    be_opts.verify_mode != VERIFY_NONE) {
                    verify_image_pattern(device->path, be_opts.pattern,
                                         be_opts.block_size,
                                         be_opts.verify_mode,
                                         &result->verify_result);
                }
                return ret;
            }

        case SANITIZE_METHOD_DEVICE_NATIVE:
            /*
             * STUB: ATA SECURITY ERASE UNIT (enhanced).
             * Requires SG_IO / hdparm protocol.
             * NOT IMPLEMENTED.
             */
            result->result_code = ERASECURE_ERR_NOT_IMPLEMENTED;
            snprintf(result->error_message, sizeof(result->error_message),
                     "ATA Secure Erase not implemented.");
            return ERASECURE_ERR_NOT_IMPLEMENTED;

        case SANITIZE_METHOD_CRYPTO_ERASE:
            result->crypto_status = crypto_erase_execute(device);
            result->result_code   = (result->crypto_status == CRYPTO_ERASE_SUCCESS)
                                    ? ERASECURE_OK : ERASECURE_ERR_NOT_IMPLEMENTED;
            return result->result_code;

        default:
            result->result_code = ERASECURE_ERR_UNSUPPORTED;
            return ERASECURE_ERR_UNSUPPORTED;
    }
}
