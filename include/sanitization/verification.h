/**
 * @file verification.h
 * @brief Post-sanitization verification API.
 *
 * SCOPE NOTICE:
 *   Logical block verification (reading back overwritten sectors) can
 *   confirm that the host-visible logical address space contains the
 *   expected pattern.  It CANNOT confirm physical NAND erasure on SSDs
 *   or flash storage, because the device's FTL (Flash Translation Layer)
 *   may remap sectors transparently.
 *
 *   VerificationResult always carries a scope field and a confidence note
 *   to ensure this limitation is not obscured in reports.
 */
#ifndef ERASECURE_VERIFICATION_H
#define ERASECURE_VERIFICATION_H

#include "common/types.h"
#include "common/error.h"
#include "sanitization/block_erase.h"
#include <stdint.h>
#include <stdbool.h>

/* ─── Scope of what was verified ─────────────────────────────── */
typedef enum {
    VERIFY_SCOPE_NOT_APPLICABLE  = 0,  /* e.g., crypto/native erase */
    VERIFY_SCOPE_LOGICAL_BLOCKS  = 1,  /* Host-visible block readback */
    VERIFY_SCOPE_SAMPLED         = 2,  /* Subset of logical blocks only */
} VerificationScope;

/* ─── Verification result record ─────────────────────────────── */
struct VerificationResult {
    VerificationScope scope;
    uint64_t          blocks_total;     /* Total blocks in image/device */
    uint64_t          blocks_checked;
    uint64_t          blocks_failed;    /* Blocks with mismatched content */
    bool              verification_passed;
    ErasecureError    result_code;

    /* Human-readable note about the scope of this verification.
     * Always set; describes limitations for SSD/flash. */
    char              confidence_note[256];
    char              error_message[128];
};

/**
 * @brief Verify that an image file contains the expected pattern.
 *
 * Reads either all blocks or a sample (depending on mode) and compares
 * each byte against the expected fill value.
 *
 * @param image_path   Path to the image file.
 * @param pattern      Expected pattern (ZERO, ONE, or RANDOM is not verifiable).
 * @param block_size   Chunk size for reads; 0 uses default.
 * @param mode         VERIFY_SAMPLE or VERIFY_FULL.
 * @param result       Output: verification statistics and outcome.
 * @return             ERASECURE_OK if verification ran (check result->blocks_failed),
 *                     ERASECURE_ERR_* if verification could not run at all.
 */
ErasecureError verify_image_pattern(const char *image_path,
                                    ErasePattern pattern,
                                    size_t block_size,
                                    VerifyMode mode,
                                    VerificationResult *result);

/**
 * @brief Return a status string for a VerificationResult.
 */
const char *verification_scope_str(VerificationScope scope);

#endif /* ERASECURE_VERIFICATION_H */
