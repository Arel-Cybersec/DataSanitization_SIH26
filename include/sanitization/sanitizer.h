/**
 * @file sanitizer.h
 * @brief Common sanitization dispatcher and GTK-ready data structures.
 *
 * The GUI/CLI calls sanitizer_run() without knowing whether the target
 * device is an HDD, SATA SSD, NVMe, USB drive, etc.  The dispatcher
 * selects the appropriate device-specific sanitizer module at runtime.
 */
#ifndef ERASECURE_SANITIZER_H
#define ERASECURE_SANITIZER_H

#include "common/types.h"
#include "common/error.h"
#include "device/device.h"
#include "sanitization/block_erase.h"
#include "sanitization/crypto_erase.h"
#include "sanitization/verification.h"
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

/* ─── Combined sanitization options ─────────────────────────── */
struct SanitizationOptions {
    SanitizationMethod   method;
    BlockEraseOptions    block_erase;
    /* crypto_erase has no tunable options in current version */
    bool                 test_mode;   /* true = image file only, not real device */

    /* Optional progress callback forwarded to block erase. */
    void (*progress_cb)(uint64_t bytes_done, uint64_t total_bytes,
                        void *user_data);
    void *user_data;
};

/* ─── Progress snapshot (poll-able by GUI) ───────────────────── */
struct SanitizationProgress {
    uint64_t bytes_done;
    uint64_t total_bytes;
    uint32_t pass_current;
    uint32_t pass_total;
    double   percentage;        /* 0.0 – 100.0 */
    bool     complete;
};

/* ─── Final sanitization result ──────────────────────────────── */
struct SanitizationResult {
    SanitizationMethod   method_used;

    /* Block erase sub-result (valid when method == BLOCK_ERASE) */
    BlockEraseResult     block_result;

    /* Crypto erase status (valid when method == CRYPTO_ERASE) */
    CryptoEraseStatus    crypto_status;

    /* Verification sub-result */
    VerificationResult   verify_result;

    /* Timestamps */
    ErasecureTimestamp   start_time;
    ErasecureTimestamp   end_time;
    double               duration_seconds;

    /* Overall outcome */
    ErasecureError       result_code;
    char                 error_message[256];
};

/**
 * @brief Initialise SanitizationOptions to safe defaults.
 */
void sanitizer_options_init(SanitizationOptions *opts);

/**
 * @brief Check whether a device supports a given sanitization method.
 *
 * Inspects device->capabilities without performing any I/O.
 *
 * @param device  Device to query.
 * @param method  Method to check.
 * @return        true if the method is supported.
 */
bool sanitizer_supports_method(const StorageDevice *device,
                               SanitizationMethod method);

/**
 * @brief Dispatch a sanitization operation to the appropriate module.
 *
 * Routes to hdd_sanitizer, ssd_sanitizer, or portable_sanitizer based
 * on device->device_type and opts->method.
 *
 * In test mode (opts->test_mode == true), the device path must be a
 * regular image file; real block-device paths are rejected.
 *
 * @param device  Device (or image file path stored in device->path).
 * @param opts    Sanitization options.
 * @param result  Output: full result record.
 * @return        ERASECURE_OK if the operation ran (check result->result_code
 *                for the sanitization outcome), ERASECURE_ERR_* if dispatch
 *                itself failed.
 */
ErasecureError sanitizer_run(const StorageDevice *device,
                             const SanitizationOptions *opts,
                             SanitizationResult *result);

#endif /* ERASECURE_SANITIZER_H */
