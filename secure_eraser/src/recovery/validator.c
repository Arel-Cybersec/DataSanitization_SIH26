#include "recovery/validator.h"
#include <stddef.h>

/**
 * @brief Run a block validator if provided.
 */
ErasecureError validator_run_block(
    BlockValidatorFn fn,
    const void *block_data, size_t block_size,
    uint32_t current_confidence,
    const void *format_state, size_t format_state_len,
    BlockValidatorResult *result
) {
    if (!fn || !result) return ERASECURE_ERROR_INVALID_ARGUMENT;
    return fn(block_data, block_size, current_confidence, format_state, format_state_len, result);
}

/**
 * @brief Run a file validator if provided.
 */
ErasecureError validator_run_file(
    FileValidatorFn fn,
    const void *candidate_data, size_t candidate_len,
    const void *format_state, size_t format_state_len,
    FileValidatorResult *result
) {
    if (!fn || !result) return ERASECURE_ERROR_INVALID_ARGUMENT;
    return fn(candidate_data, candidate_len, format_state, format_state_len, result);
}

/**
 * @brief Convert validation outcome to string.
 */
const char *file_validation_outcome_str(FileValidationOutcome outcome) {
    switch (outcome) {
        case FILE_VALIDATION_PROMISING:    return "PROMISING";
        case FILE_VALIDATION_VALIDATES_TO: return "VALIDATES_TO";
        case FILE_VALIDATION_VALIDATES:    return "VALIDATES";
        case FILE_VALIDATION_INVALID:      return "INVALID";
        default:                           return "UNKNOWN";
    }
}
