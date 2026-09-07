#ifndef ERASECURE_VALIDATOR_H
#define ERASECURE_VALIDATOR_H

#include "common/types.h"
#include "common/error.h"
#include "recovery/block_state.h"
#include <stdint.h>
#include <stdbool.h>

/* ─── Block Validator ───────────────────────────────────────── */
typedef struct {
    uint32_t         confidence;    /* Updated confidence (0-100) */
    BlockValidation  validation;    /* VALID / INVALID / UNKNOWN */
    void            *state_out;     /* Optional format state output (caller frees) */
    size_t           state_out_len;
} BlockValidatorResult;

typedef ErasecureError (*BlockValidatorFn)(
    const void *block_data,
    size_t block_size,
    uint32_t current_confidence,
    const void *format_state,
    size_t format_state_len,
    BlockValidatorResult *result
);

/* ─── File Validator ────────────────────────────────────────── */
typedef enum {
    FILE_VALIDATION_PROMISING     = 0,  /* Partial match, continue */
    FILE_VALIDATION_VALIDATES_TO  = 1,  /* Identifies truncation point */
    FILE_VALIDATION_VALIDATES     = 2,  /* Complete valid file */
    FILE_VALIDATION_INVALID       = 3,  /* Not a valid file */
} FileValidationOutcome;

typedef struct {
    FileValidationOutcome outcome;
    uint64_t              validated_length;  /* Bytes validated so far */
    uint32_t              confidence;
    char                  detail[256];       /* Human-readable detail */
} FileValidatorResult;
typedef FileValidatorResult FileValidationResult;

typedef ErasecureError (*FileValidatorFn)(
    const void *candidate_data,
    size_t candidate_len,
    const void *format_state,
    size_t format_state_len,
    FileValidatorResult *result
);

/* ─── Convenience wrappers ──────────────────────────────────── */
ErasecureError validator_run_block(
    BlockValidatorFn fn,
    const void *block_data, size_t block_size,
    uint32_t current_confidence,
    const void *format_state, size_t format_state_len,
    BlockValidatorResult *result
);

ErasecureError validator_run_file(
    FileValidatorFn fn,
    const void *candidate_data, size_t candidate_len,
    const void *format_state, size_t format_state_len,
    FileValidatorResult *result
);

const char *file_validation_outcome_str(FileValidationOutcome outcome);

#endif
