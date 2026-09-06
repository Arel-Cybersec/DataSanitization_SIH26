/**
 * @file sanitizer.c
 * @brief Central sanitization dispatcher.
 */
#include "sanitization/sanitizer.h"
#include "hdd/hdd_sanitizer.h"
#include "ssd/ssd_sanitizer.h"
#include "portable/portable_sanitizer.h"
#include "common/error.h"

#include <string.h>
#include <time.h>

void sanitizer_options_init(SanitizationOptions *opts)
{
    if (!opts) return;
    memset(opts, 0, sizeof(*opts));
    opts->method    = SANITIZE_METHOD_BLOCK_ERASE;
    opts->test_mode = true;  /* safe default */
    block_erase_options_init(&opts->block_erase);
}

bool sanitizer_supports_method(const StorageDevice *device,
                               SanitizationMethod method)
{
    if (!device) return false;

    switch (method) {
        case SANITIZE_METHOD_BLOCK_ERASE:
            return device->capabilities.supports_block_erase;
        case SANITIZE_METHOD_CRYPTO_ERASE:
            return device->capabilities.supports_crypto_erase;
        case SANITIZE_METHOD_DEVICE_NATIVE:
            return device->capabilities.supports_device_native;
        default:
            return false;
    }
}

ErasecureError sanitizer_run(const StorageDevice *device,
                             const SanitizationOptions *opts,
                             SanitizationResult *result)
{
    if (!device || !opts || !result) return ERASECURE_ERR_INVALID_ARG;

    memset(result, 0, sizeof(*result));
    result->result_code = ERASECURE_ERR_GENERIC;
    result->method_used = opts->method;
    result->start_time  = time(NULL);

    ErasecureError ret = ERASECURE_ERR_GENERIC;

    /* Route to device-specific module */
    if (hdd_can_handle(device)) {
        ret = hdd_sanitize(device, opts, result);
    } else if (ssd_can_handle(device)) {
        ret = ssd_sanitize(device, opts, result);
    } else if (portable_can_handle(device)) {
        ret = portable_sanitize(device, opts, result);
    } else {
        /* Unknown device type: attempt block erase in test mode only */
        if (opts->test_mode && opts->method == SANITIZE_METHOD_BLOCK_ERASE) {
            ret = block_erase_image(device->path, &opts->block_erase,
                                    &result->block_result);
            result->result_code = ret;
        } else {
            result->result_code = ERASECURE_ERR_UNSUPPORTED;
            ret = ERASECURE_ERR_UNSUPPORTED;
        }
    }

    result->end_time = time(NULL);
    result->duration_seconds =
        difftime(result->end_time, result->start_time);

    return ret;
}
