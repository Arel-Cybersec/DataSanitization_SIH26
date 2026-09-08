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
#include "device/device.h"
#include "crypto/key_management.h"
#include "common/constants.h"
#include "common/error.h"

#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

#ifdef __linux__
#include <sys/ioctl.h>
#include <linux/fs.h>
#endif

/* ─── Pattern fill helpers ───────────────────────────────────── */

ErasecureError block_erase_fill_pattern(uint8_t *buf, size_t len,
                                        ErasePattern pattern)
{
    if (!buf) return ERASECURE_ERR_NULL_PTR;

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

static ErasecureError fill_buffer_pattern(uint8_t *buf, size_t len,
                                          ErasePattern pattern)
{
    return block_erase_fill_pattern(buf, len, pattern);
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

ErasecureError block_erase_device(const StorageDevice *device,
                                 const BlockEraseOptions *opts,
                                 const char *confirmation,
                                 BlockEraseResult *result)
{
    if (!device || !opts || !result || !confirmation) {
        return ERASECURE_ERR_INVALID_ARG;
    }

    memset(result, 0, sizeof(*result));
    result->result_code = ERASECURE_ERR_GENERIC;

    /* SAFETY CHECK 1: Confirmation token must match exact device path */
    if (strcmp(confirmation, device->path) != 0) {
        result->result_code = ERASECURE_ERR_CONFIRMATION;
        snprintf(result->error_message, sizeof(result->error_message),
                 "SAFETY: Confirmation token '%s' does not match device path '%s'",
                 confirmation, device->path);
        return ERASECURE_ERR_CONFIRMATION;
    }

    /* SAFETY CHECK 2: Must be a recognized physical block device path */
    if (!device_path_is_block_device(device->path)) {
        result->result_code = ERASECURE_ERR_NOT_A_DEVICE;
        snprintf(result->error_message, sizeof(result->error_message),
                 "SAFETY: '%s' is not recognized as a physical block device",
                 device->path);
        return ERASECURE_ERR_NOT_A_DEVICE;
    }

    /* SAFETY CHECK 3: Must not be marked read-only */
    if (device->is_read_only) {
        result->result_code = ERASECURE_ERR_DEVICE_READ_ONLY;
        snprintf(result->error_message, sizeof(result->error_message),
                 "SAFETY: Device '%s' is reported read-only", device->path);
        return ERASECURE_ERR_DEVICE_READ_ONLY;
    }

    /* SAFETY CHECK 4: Device or its partitions must NOT be mounted */
    bool is_mounted = false;
    ErasecureError mnt_err = device_is_mounted(device->path, &is_mounted);
    if (mnt_err == ERASECURE_OK && is_mounted) {
        result->result_code = ERASECURE_ERR_DEVICE_MOUNTED;
        snprintf(result->error_message, sizeof(result->error_message),
                 "SAFETY: Device '%s' or one of its partitions is mounted. Refusing erasure.",
                 device->path);
        return ERASECURE_ERR_DEVICE_MOUNTED;
    }

#ifdef __linux__
    /* Check options and clamp */
    size_t block_size = opts->block_size;
    if (block_size < ERASECURE_MIN_BLOCK_SIZE) block_size = ERASECURE_DEFAULT_BLOCK_SIZE;
    if (block_size > ERASECURE_MAX_BLOCK_SIZE) block_size = ERASECURE_MAX_BLOCK_SIZE;

    uint32_t passes = opts->passes;
    if (passes == 0) passes = ERASECURE_DEFAULT_PASSES;
    if (passes > ERASECURE_MAX_PASSES) passes = ERASECURE_MAX_PASSES;

    int open_flags = O_RDWR | O_SYNC;
#ifdef O_EXCL
    open_flags |= O_EXCL;
#endif
#ifdef O_LARGEFILE
    open_flags |= O_LARGEFILE;
#endif

    int fd = open(device->path, open_flags);
    if (fd < 0) {
        if (errno == EACCES || errno == EPERM) {
            result->result_code = ERASECURE_ERR_PERMISSION_DENIED;
            snprintf(result->error_message, sizeof(result->error_message),
                     "Permission denied opening '%s'. Root privileges required.", device->path);
            return ERASECURE_ERR_PERMISSION_DENIED;
        } else if (errno == EBUSY) {
            result->result_code = ERASECURE_ERR_DEVICE_BUSY;
            snprintf(result->error_message, sizeof(result->error_message),
                     "Device '%s' is busy or held exclusively by another process.", device->path);
            return ERASECURE_ERR_DEVICE_BUSY;
        }
        result->result_code = ERASECURE_ERR_OPEN_FAILED;
        snprintf(result->error_message, sizeof(result->error_message),
                 "open('%s') failed: %s", device->path, strerror(errno));
        return ERASECURE_ERR_OPEN_FAILED;
    }

    /* Query actual device capacity via BLKGETSIZE64 ioctl */
    uint64_t dev_capacity = device->capacity_bytes;
#ifdef BLKGETSIZE64
    uint64_t ioctl_size = 0;
    if (ioctl(fd, BLKGETSIZE64, &ioctl_size) == 0 && ioctl_size > 0) {
        dev_capacity = ioctl_size;
    }
#endif

    if (dev_capacity == 0) {
        close(fd);
        result->result_code = ERASECURE_ERR_DEVICE_SCAN_FAIL;
        snprintf(result->error_message, sizeof(result->error_message),
                 "Device '%s' reported zero capacity", device->path);
        return ERASECURE_ERR_DEVICE_SCAN_FAIL;
    }

    uint8_t *buf = malloc(block_size);
    if (!buf) {
        close(fd);
        result->result_code = ERASECURE_ERR_ALLOC;
        snprintf(result->error_message, sizeof(result->error_message),
                 "Failed to allocate %zu-byte I/O buffer", block_size);
        return ERASECURE_ERR_ALLOC;
    }

    uint64_t total_bytes_to_write = dev_capacity * passes;
    uint64_t bytes_written_total  = 0;
    ErasecureError ret = ERASECURE_OK;

    struct timespec ts_start, ts_end;
    clock_gettime(CLOCK_MONOTONIC, &ts_start);

    for (uint32_t pass = 1; pass <= passes && ret == ERASECURE_OK; ++pass) {
        if (lseek(fd, 0, SEEK_SET) == (off_t)-1) {
            ret = ERASECURE_ERR_SEEK_FAILED;
            snprintf(result->error_message, sizeof(result->error_message),
                     "lseek failed on pass %u: %s", pass, strerror(errno));
            break;
        }

        uint64_t remaining = dev_capacity;
        while (remaining > 0 && ret == ERASECURE_OK) {
            size_t chunk = (remaining < (uint64_t)block_size)
                           ? (size_t)remaining
                           : block_size;

            ErasecureError fill_err = fill_buffer_pattern(buf, chunk, opts->pattern);
            if (fill_err != ERASECURE_OK) {
                ret = fill_err;
                break;
            }

            size_t chunk_written = 0;
            while (chunk_written < chunk) {
                ssize_t w = write(fd, buf + chunk_written, chunk - chunk_written);
                if (w < 0) {
                    if (errno == EINTR) continue;
                    ret = ERASECURE_ERR_WRITE_FAILED;
                    snprintf(result->error_message, sizeof(result->error_message),
                             "write() failed at pass %u: %s", pass, strerror(errno));
                    break;
                }
                if (w == 0) {
                    ret = ERASECURE_ERR_WRITE_FAILED;
                    snprintf(result->error_message, sizeof(result->error_message),
                             "write() returned 0 unexpectedly at pass %u", pass);
                    break;
                }
                chunk_written += (size_t)w;
            }

            if (ret != ERASECURE_OK) break;

            bytes_written_total += (uint64_t)chunk;
            remaining           -= (uint64_t)chunk;

            if (opts->progress_cb) {
                opts->progress_cb(bytes_written_total, total_bytes_to_write, opts->user_data);
            }
        }

        /* Flush each pass to physical media */
        if (ret == ERASECURE_OK) {
            if (fsync(fd) != 0) {
                ret = ERASECURE_ERR_SYNC_FAILED;
                snprintf(result->error_message, sizeof(result->error_message),
                         "fsync failed at pass %u: %s", pass, strerror(errno));
            } else {
                result->passes_completed++;
            }
        }
    }

    close(fd);
    key_mgmt_secure_cleanse(buf, block_size);
    free(buf);

    clock_gettime(CLOCK_MONOTONIC, &ts_end);
    result->duration_seconds =
        (double)(ts_end.tv_sec  - ts_start.tv_sec) +
        (double)(ts_end.tv_nsec - ts_start.tv_nsec) * 1e-9;
    result->bytes_written = bytes_written_total;
    result->result_code   = ret;

    return ret;
#else
    (void)device;
    (void)opts;
    (void)confirmation;
    result->result_code = ERASECURE_ERR_UNSUPPORTED;
    snprintf(result->error_message, sizeof(result->error_message),
             "Physical block device erasure is only supported on Linux.");
    return ERASECURE_ERR_UNSUPPORTED;
#endif
}
