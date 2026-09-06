/**
 * @file block_erase.h
 * @brief Safe block-level pattern overwrite API.
 *
 * IMPORTANT — TEST-IMAGE SAFETY:
 *   In the current implementation, block_erase_image() operates ONLY on
 *   regular files (disk images).  It explicitly rejects paths that
 *   match known physical block-device prefixes (e.g., /dev/sd*, /dev/nvme*).
 *
 *   Physical-device block erase is NOT implemented in this version.
 */
#ifndef ERASECURE_BLOCK_ERASE_H
#define ERASECURE_BLOCK_ERASE_H

#include "common/types.h"
#include "common/error.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* ─── Erase patterns ─────────────────────────────────────────── */
typedef enum {
    ERASE_PATTERN_ZERO   = 0,   /* Fill with 0x00 */
    ERASE_PATTERN_ONE    = 1,   /* Fill with 0xFF */
    ERASE_PATTERN_RANDOM = 2,   /* Cryptographically random bytes (OpenSSL) */
} ErasePattern;

/* ─── Verification mode ──────────────────────────────────────── */
typedef enum {
    VERIFY_NONE    = 0,   /* No readback verification */
    VERIFY_SAMPLE  = 1,   /* Sample a fixed number of blocks */
    VERIFY_FULL    = 2,   /* Read back every block written */
} VerifyMode;

/* ─── Options passed by caller ───────────────────────────────── */
typedef struct {
    ErasePattern pattern;
    size_t       block_size;    /* Bytes per I/O chunk; 0 = use default */
    uint32_t     passes;        /* Number of overwrite passes; 0 = use default */
    VerifyMode   verify_mode;
    /** Optional progress callback; NULL to disable.
     *  @param bytes_done   Bytes written so far (cumulative across passes).
     *  @param total_bytes  Total bytes to write (passes × size).
     *  @param user_data    Opaque pointer from BlockEraseOptions.user_data. */
    void (*progress_cb)(uint64_t bytes_done, uint64_t total_bytes,
                        void *user_data);
    void *user_data;
} BlockEraseOptions;

/* ─── Result ─────────────────────────────────────────────────── */
typedef struct {
    uint64_t      bytes_written;
    uint32_t      passes_completed;
    double        duration_seconds;
    ErasecureError result_code;
    char          error_message[128];
} BlockEraseResult;

/**
 * @brief Fill a disk-image file with the selected pattern.
 *
 * Refuses to operate on paths matching physical block-device prefixes.
 * Opens the file, writes in chunks of opts->block_size (or default),
 * calls fsync(), and optionally verifies the written content.
 *
 * @param image_path  Path to a regular file (disk image).
 * @param opts        Erase options.
 * @param result      Output: populated with bytes_written, duration, etc.
 * @return            ERASECURE_OK on success,
 *                    ERASECURE_ERR_REAL_DEVICE_PATH if path is a block device,
 *                    other ERASECURE_ERR_* on failure.
 */
ErasecureError block_erase_image(const char *image_path,
                                 const BlockEraseOptions *opts,
                                 BlockEraseResult *result);

/**
 * @brief Return a human-readable name for an ErasePattern.
 */
const char *erase_pattern_str(ErasePattern pattern);

/**
 * @brief Initialise BlockEraseOptions to safe defaults.
 */
void block_erase_options_init(BlockEraseOptions *opts);

#endif /* ERASECURE_BLOCK_ERASE_H */
