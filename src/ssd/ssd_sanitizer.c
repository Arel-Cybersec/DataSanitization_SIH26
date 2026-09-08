/**
 * @file ssd_sanitizer.c
 * @brief SSD sanitization (SATA SSD and NVMe SSD).
 *
 * IMPORTANT: Block overwrite on SSDs does NOT guarantee physical NAND erasure.
 * Device-native sanitization (ATA Sanitize / NVMe Sanitize) is STUBBED.
 */
#include "ssd/ssd_sanitizer.h"
#include "sanitization/block_erase.h"
#include "sanitization/verification.h"
#include "sanitization/crypto_erase.h"
#include "common/error.h"

#include <string.h>
#include <stdio.h>

const char *ssd_sanitize_status_str(SsdSanitizeStatus status)
{
    switch (status) {
        case SSD_SANITIZE_SUCCESS:           return "Success";
        case SSD_SANITIZE_UNSUPPORTED:       return "Unsupported";
        case SSD_SANITIZE_NOT_IMPLEMENTED:   return "Not implemented";
        case SSD_SANITIZE_FAILED:            return "Failed";
        case SSD_SANITIZE_DEVICE_ERROR:      return "Device error";
        case SSD_SANITIZE_LOGICAL_ONLY_WARN: return "Logical overwrite only (NAND not guaranteed)";
        default:                             return "Unknown";
    }
}

bool ssd_can_handle(const StorageDevice *device)
{
    if (!device) return false;
    return (device->device_type == DEVICE_TYPE_SATA_SSD ||
            device->device_type == DEVICE_TYPE_NVME_SSD);
}

bool ssd_supports_method(const StorageDevice *device, SanitizationMethod method)
{
    if (!device) return false;
    switch (method) {
        case SANITIZE_METHOD_BLOCK_ERASE:
            /* Logical overwrite supported, but NAND guarantee requires native cmd */
            return !device->is_read_only;
        case SANITIZE_METHOD_CRYPTO_ERASE:
            return device->capabilities.supports_crypto_erase;
        case SANITIZE_METHOD_DEVICE_NATIVE:
            return device->capabilities.supports_device_native;
        default:
            return false;
    }
}

ErasecureError ssd_sanitize(const StorageDevice *device,
                            const SanitizationOptions *opts,
                            SanitizationResult *result)
{
    if (!device || !opts || !result) return ERASECURE_ERR_INVALID_ARG;

    result->method_used = opts->method;

    switch (opts->method) {
        case SANITIZE_METHOD_BLOCK_ERASE:
            if (!opts->test_mode) {
                /* Real SSD logical block overwrite with explicit confirmation.
                 * Note: Physical NAND erasure limitation is documented in the result. */
                BlockEraseOptions be_opts = opts->block_erase;
                be_opts.progress_cb = opts->progress_cb;
                be_opts.user_data   = opts->user_data;

                ErasecureError ret = block_erase_device(device, &be_opts,
                                                        device->path,
                                                        &result->block_result);
                result->result_code = ret;
                snprintf(result->verify_result.confidence_note,
                         sizeof(result->verify_result.confidence_note),
                         "CAVEAT: Logical block overwrite completed, but cannot guarantee "
                         "physical NAND erasure due to SSD Flash Translation Layer (FTL) "
                         "and wear-leveling remaps.");
                return ret;
            }
            /* Test image mode */
            {
                BlockEraseOptions be_opts = opts->block_erase;
                be_opts.progress_cb = opts->progress_cb;
                be_opts.user_data   = opts->user_data;

                ErasecureError ret = block_erase_image(device->path, &be_opts,
                                                       &result->block_result);
                result->result_code = ret;

                /* Note limitation in result */
                snprintf(result->error_message, sizeof(result->error_message),
                         "SSD: test-image logical overwrite complete. "
                         "NAND physical erasure NOT confirmed by this method.");

                if (ret == ERASECURE_OK && be_opts.verify_mode != VERIFY_NONE) {
                    verify_image_pattern(device->path, be_opts.pattern,
                                         be_opts.block_size, be_opts.verify_mode,
                                         &result->verify_result);
                }
                return ret;
            }

        case SANITIZE_METHOD_DEVICE_NATIVE:
            if (device->device_type == DEVICE_TYPE_NVME_SSD) {
                /*
                 * STUB: NVMe Sanitize (SANACT) or Format NVM (ses=2).
                 * Requires: NVME_IOCTL_ADMIN_CMD ioctl, root privileges,
                 * careful handling of sanitize progress monitoring.
                 * NOT IMPLEMENTED.
                 */
                result->result_code = ERASECURE_ERR_NOT_IMPLEMENTED;
                snprintf(result->error_message, sizeof(result->error_message),
                         "NVMe Sanitize / Format NVM not implemented.");
            } else {
                /*
                 * STUB: SATA ATA Sanitize command.
                 * Requires: SG_IO with ATA-16 passthrough.
                 * NOT IMPLEMENTED.
                 */
                result->result_code = ERASECURE_ERR_NOT_IMPLEMENTED;
                snprintf(result->error_message, sizeof(result->error_message),
                         "SATA ATA Sanitize not implemented.");
            }
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
