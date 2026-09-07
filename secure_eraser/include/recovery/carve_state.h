#ifndef ERASECURE_CARVE_STATE_H
#define ERASECURE_CARVE_STATE_H

#include "common/types.h"
#include "common/error.h"
#include "recovery/blockvector.h"
#include <stdint.h>
#include <stdbool.h>

typedef enum {
    CANDIDATE_STATUS_NEW         = 0,
    CANDIDATE_STATUS_SCANNING    = 1,
    CANDIDATE_STATUS_PROMISING   = 2,
    CANDIDATE_STATUS_VALIDATING  = 3,
    CANDIDATE_STATUS_VALIDATED   = 4,
    CANDIDATE_STATUS_FAILED      = 5,
    CANDIDATE_STATUS_CANCELLED   = 6,
} CandidateStatus;

typedef enum {
    VALIDATION_RESULT_UNKNOWN    = 0,
    VALIDATION_RESULT_PROMISING  = 1,
    VALIDATION_RESULT_VALIDATES_TO = 2,
    VALIDATION_RESULT_VALIDATES  = 3,
    VALIDATION_RESULT_INVALID    = 4,
} ValidationResult;

struct CarveState {
    char               uuid[37];          /* Unique candidate identifier */
    char               file_type[32];     /* e.g. "JPEG", "PNG" */
    uint64_t           start_block;       /* First block of candidate */
    Blockvector        blockvector;        /* Block sequence */
    uint64_t           candidate_length;  /* Expected/estimated file length */
    CandidateStatus    status;
    ValidationResult   validation;
    uint32_t           confidence;        /* 0-100 */
    uint32_t           priority;          /* Queue priority */
    uint64_t           service_time_us;   /* Accumulated CPU time */
    uint64_t           reassembly_pos;    /* Current reassembly position (block index) */
    /* Opaque format-specific state */
    void              *format_state;
    size_t             format_state_len;
    /* Checkpoint info */
    uint64_t           checkpoint_seq;    /* Last checkpoint sequence */
};

/**
 * @brief Generate a random UUID string (8-4-4-4-12 format).
 */
ErasecureError generate_uuid(char *buf, size_t buf_len);

/**
 * @brief Initialize a new carve state.
 */
ErasecureError carve_state_create(CarveState *cs, const char *file_type, uint64_t start_block);

/**
 * @brief Free resources associated with a carve state.
 */
void carve_state_free(CarveState *cs);

/**
 * @brief Set opaque format-specific state for a candidate.
 */
ErasecureError carve_state_set_format_state(CarveState *cs, const void *data, size_t len);

/**
 * @brief Get human-readable candidate status string.
 */
const char *candidate_status_str(CandidateStatus status);

/**
 * @brief Get human-readable validation result string.
 */
const char *validation_result_str(ValidationResult result);

#endif /* ERASECURE_CARVE_STATE_H */
