/**
 * @file verification.c
 * @brief Post-sanitization logical block verification.
 *
 * NOTE: This verifies HOST-VISIBLE logical blocks only.
 *       It cannot confirm physical NAND erasure on flash-based devices.
 */
#define _POSIX_C_SOURCE 200809L
#define _FILE_OFFSET_BITS 64

#include "sanitization/verification.h"
#include "common/constants.h"
#include "common/error.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <errno.h>

const char *verification_scope_str(VerificationScope scope)
{
    switch (scope) {
        case VERIFY_SCOPE_NOT_APPLICABLE: return "Not applicable";
        case VERIFY_SCOPE_LOGICAL_BLOCKS: return "Logical block readback (full)";
        case VERIFY_SCOPE_SAMPLED:        return "Logical block readback (sampled)";
        default:                          return "Unknown";
    }
}

/* ─── Internal: verify a file against a constant fill byte ───── */

static ErasecureError verify_constant_pattern(const char *image_path,
                                              uint8_t expected_byte,
                                              size_t block_size,
                                              VerifyMode mode,
                                              VerificationResult *result)
{
    struct stat st;
    if (stat(image_path, &st) != 0) {
        return ERASECURE_ERR_STAT_FAILED;
    }
    uint64_t file_size = (uint64_t)st.st_size;
    if (file_size == 0) return ERASECURE_ERR_INVALID_ARG;

    uint64_t total_blocks = file_size / block_size;
    if (file_size % block_size != 0) total_blocks++;

    result->blocks_total   = total_blocks;
    result->blocks_checked = 0;
    result->blocks_failed  = 0;

    /* For SAMPLE mode, check every Nth block */
    uint64_t sample_step = 1;
    if (mode == VERIFY_SAMPLE && total_blocks > ERASECURE_VERIFY_SAMPLE_BLOCKS) {
        sample_step = total_blocks / ERASECURE_VERIFY_SAMPLE_BLOCKS;
    }

    uint8_t *buf = malloc(block_size);
    if (!buf) return ERASECURE_ERR_ALLOC;

    FILE *f = fopen(image_path, "rb");
    if (!f) { free(buf); return ERASECURE_ERR_OPEN_FAILED; }

    ErasecureError ret = ERASECURE_OK;

    for (uint64_t blk = 0; blk < total_blocks; blk += sample_step) {
        /* Seek to block */
        if (fseeko(f, (off_t)(blk * block_size), SEEK_SET) != 0) {
            ret = ERASECURE_ERR_SEEK_FAILED;
            break;
        }

        /* Compute remaining size for last block */
        uint64_t offset = blk * block_size;
        size_t to_read = (file_size - offset < block_size)
                         ? (size_t)(file_size - offset)
                         : block_size;

        size_t n = fread(buf, 1, to_read, f);
        if (n != to_read) {
            ret = ERASECURE_ERR_READ_FAILED;
            break;
        }

        result->blocks_checked++;

        /* Compare every byte */
        bool block_ok = true;
        for (size_t i = 0; i < n; ++i) {
            if (buf[i] != expected_byte) {
                block_ok = false;
                break;
            }
        }
        if (!block_ok) {
            result->blocks_failed++;
        }
    }

    fclose(f);
    free(buf);

    result->verification_passed = (result->blocks_failed == 0);
    result->result_code         = ret;
    result->scope = (mode == VERIFY_SAMPLE)
                    ? VERIFY_SCOPE_SAMPLED
                    : VERIFY_SCOPE_LOGICAL_BLOCKS;
    return ret;
}

/* ─── Public API ─────────────────────────────────────────────── */

ErasecureError verify_image_pattern(const char *image_path,
                                    ErasePattern pattern,
                                    size_t block_size,
                                    VerifyMode mode,
                                    VerificationResult *result)
{
    if (!image_path || !result) return ERASECURE_ERR_INVALID_ARG;

    memset(result, 0, sizeof(*result));
    result->result_code = ERASECURE_ERR_GENERIC;

    /* RANDOM pattern cannot be verified by readback */
    if (pattern == ERASE_PATTERN_RANDOM) {
        result->scope = VERIFY_SCOPE_NOT_APPLICABLE;
        result->verification_passed = false;
        snprintf(result->confidence_note, sizeof(result->confidence_note),
                 "Random pattern verification is not possible: "
                 "the written values are not deterministic.");
        snprintf(result->error_message, sizeof(result->error_message),
                 "Cannot verify random pattern.");
        result->result_code = ERASECURE_ERR_UNSUPPORTED;
        return ERASECURE_ERR_UNSUPPORTED;
    }

    if (block_size < ERASECURE_MIN_BLOCK_SIZE) {
        block_size = ERASECURE_DEFAULT_BLOCK_SIZE;
    }
    if (block_size > ERASECURE_MAX_BLOCK_SIZE) {
        block_size = ERASECURE_MAX_BLOCK_SIZE;
    }

    uint8_t expected = (pattern == ERASE_PATTERN_ZERO) ? 0x00U : 0xFFU;

    ErasecureError ret = verify_constant_pattern(image_path, expected,
                                                 block_size, mode, result);

    /* Always set the scope limitation note */
    snprintf(result->confidence_note, sizeof(result->confidence_note),
             "Verification scope: %s. "
             "Logical block readback confirms host-visible content only. "
             "Physical NAND erasure on SSD/flash devices cannot be "
             "confirmed by this method.",
             verification_scope_str(result->scope));

    return ret;
}
