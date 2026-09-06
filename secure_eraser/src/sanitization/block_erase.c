/**
 * @file block_erase.c
 * @brief Safe block-level pattern overwrite for disk images.
 *
 * This implementation operates ONLY on regular files.
 * Physical block devices are explicitly rejected.
 */
#define _POSIX_C_SOURCE 200809L
#define _FILE_OFFSET_BITS 64

#include "sanitization/block_erase.h"
#include "device/device_detect.h"
#include "common/constants.h"
#include "common/error.h"

#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>

/* ─── Pattern fill helpers ───────────────────────────────────── */

static ErasecureError fill_buffer_pattern(uint8_t *buf, size_t len,
                                          ErasePattern pattern)
{
    switch (pattern) {
        case ERASE_PATTERN_ZERO:
            memset(buf, 0x00, len);
            return ERASECURE_OK;

        case ERASE_PATTERN_ONE:
            memset(buf, 0xFF, len);
            return ERASECURE_OK;

        case ERASE_PATTERN_RANDOM:
            if (RAND_bytes(buf, (int)len) != 1) {
                return ERASECURE_ERR_CRYPTO;
            }
            return ERASECURE_OK;

        default:
            return ERASECURE_ERR_INVALID_ARG;
    }
}

/* ─── String helpers ─────────────────────────────────────────── */

const char *erase_pattern_str(ErasePattern pattern)
{
    switch (pattern) {
        case ERASE_PATTERN_ZERO:   return "zero (0x00)";
        case ERASE_PATTERN_ONE:    return "one (0xFF)";
        case ERASE_PATTERN_RANDOM: return "random (CSPRNG)";
        default:                   return "unknown";
    }
}

void block_erase_options_init(BlockEraseOptions *opts)
{
    if (!opts) return;
    memset(opts, 0, sizeof(*opts));
    opts->pattern    = ERASE_PATTERN_ZERO;
    opts->block_size = ERASECURE_DEFAULT_BLOCK_SIZE;
    opts->passes     = ERASECURE_DEFAULT_PASSES;
    opts->verify_mode = VERIFY_NONE;
}

/* ─── Main implementation ────────────────────────────────────── */

ErasecureError block_erase_image(const char *image_path,
                                 const BlockEraseOptions *opts,
                                 BlockEraseResult *result)
{
    /* ── Argument validation ── */
    if (!image_path || !opts || !result) {
        return ERASECURE_ERR_INVALID_ARG;
    }

    memset(result, 0, sizeof(*result));
    result->result_code = ERASECURE_ERR_GENERIC;

    /* ── SAFETY CHECK: reject physical block-device paths ── */
    if (device_path_is_block_device(image_path)) {
        result->result_code = ERASECURE_ERR_REAL_DEVICE_PATH;
        snprintf(result->error_message, sizeof(result->error_message),
                 "SAFETY: '%s' looks like a physical block device. "
                 "block_erase_image() is for test images only.", image_path);
        return ERASECURE_ERR_REAL_DEVICE_PATH;
    }

    /* ── Validate and clamp options ── */
    size_t block_size = opts->block_size;
    if (block_size < ERASECURE_MIN_BLOCK_SIZE) {
        block_size = ERASECURE_DEFAULT_BLOCK_SIZE;
    }
    if (block_size > ERASECURE_MAX_BLOCK_SIZE) {
        block_size = ERASECURE_MAX_BLOCK_SIZE;
    }

    uint32_t passes = opts->passes;
    if (passes == 0) passes = ERASECURE_DEFAULT_PASSES;
    if (passes > ERASECURE_MAX_PASSES) passes = ERASECURE_MAX_PASSES;

    /* ── Stat the file to get size ── */
    struct stat st;
    if (stat(image_path, &st) != 0) {
        result->result_code = ERASECURE_ERR_STAT_FAILED;
        snprintf(result->error_message, sizeof(result->error_message),
                 "stat('%s') failed: %s", image_path, strerror(errno));
        return ERASECURE_ERR_STAT_FAILED;
    }

    if (!S_ISREG(st.st_mode)) {
        result->result_code = ERASECURE_ERR_INVALID_ARG;
        snprintf(result->error_message, sizeof(result->error_message),
                 "'%s' is not a regular file.", image_path);
        return ERASECURE_ERR_INVALID_ARG;
    }

    uint64_t file_size = (uint64_t)st.st_size;
    if (file_size == 0) {
        result->result_code = ERASECURE_ERR_INVALID_ARG;
        snprintf(result->error_message, sizeof(result->error_message),
                 "'%s' has zero size.", image_path);
        return ERASECURE_ERR_INVALID_ARG;
    }

    /* ── Allocate write buffer ── */
    uint8_t *buf = malloc(block_size);
    if (!buf) {
        result->result_code = ERASECURE_ERR_ALLOC;
        snprintf(result->error_message, sizeof(result->error_message),
                 "malloc(%zu) failed.", block_size);
        return ERASECURE_ERR_ALLOC;
    }

    /* ── Timing ── */
    struct timespec ts_start, ts_end;
    clock_gettime(CLOCK_MONOTONIC, &ts_start);

    uint64_t total_bytes_to_write = file_size * (uint64_t)passes;
    uint64_t bytes_written_total  = 0;

    ErasecureError ret = ERASECURE_OK;

    /* ── Pass loop ── */
    for (uint32_t pass = 0; pass < passes && ret == ERASECURE_OK; ++pass) {

        FILE *f = fopen(image_path, "r+b");
        if (!f) {
            ret = ERASECURE_ERR_OPEN_FAILED;
            snprintf(result->error_message, sizeof(result->error_message),
                     "fopen('%s') failed: %s", image_path, strerror(errno));
            break;
        }

        uint64_t remaining = file_size;

        while (remaining > 0 && ret == ERASECURE_OK) {
            size_t chunk = (remaining < block_size) ? (size_t)remaining : block_size;

            /* Generate pattern for this chunk */
            ErasecureError pe = fill_buffer_pattern(buf, chunk, opts->pattern);
            if (pe != ERASECURE_OK) {
                ret = pe;
                snprintf(result->error_message, sizeof(result->error_message),
                         "Pattern generation failed.");
                break;
            }

            /* Write chunk */
            size_t written = fwrite(buf, 1, chunk, f);
            if (written != chunk) {
                ret = ERASECURE_ERR_WRITE_FAILED;
                snprintf(result->error_message, sizeof(result->error_message),
                         "fwrite failed at pass %u: %s", pass, strerror(errno));
                break;
            }

            bytes_written_total += (uint64_t)written;
            remaining           -= (uint64_t)written;

            /* Progress callback */
            if (opts->progress_cb) {
                opts->progress_cb(bytes_written_total,
                                  total_bytes_to_write,
                                  opts->user_data);
            }
        }

        /* fsync to flush to storage */
        if (ret == ERASECURE_OK) {
            if (fflush(f) != 0 || fsync(fileno(f)) != 0) {
                ret = ERASECURE_ERR_SYNC_FAILED;
                snprintf(result->error_message, sizeof(result->error_message),
                         "fsync failed at pass %u: %s", pass, strerror(errno));
            }
        }

        fclose(f);

        if (ret == ERASECURE_OK) {
            result->passes_completed++;
        }
    }

    /* ── Timing ── */
    clock_gettime(CLOCK_MONOTONIC, &ts_end);
    result->duration_seconds =
        (double)(ts_end.tv_sec  - ts_start.tv_sec) +
        (double)(ts_end.tv_nsec - ts_start.tv_nsec) * 1e-9;

    result->bytes_written = bytes_written_total;
    result->result_code   = ret;

    free(buf);
    return ret;
}
