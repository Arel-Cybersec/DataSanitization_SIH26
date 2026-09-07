#include "recovery/carve_state.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

ErasecureError generate_uuid(char *buf, size_t buf_len) {
    if (!buf || buf_len < 37) return ERASECURE_ERR_INVALID_ARG;
    
    unsigned char r[16];
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return ERASECURE_ERR_IO;
    
    if (read(fd, r, sizeof(r)) != sizeof(r)) {
        close(fd);
        return ERASECURE_ERR_IO;
    }
    close(fd);
    
    // Set version 4 and variant
    r[6] = (r[6] & 0x0f) | 0x40;
    r[8] = (r[8] & 0x3f) | 0x80;
    
    snprintf(buf, buf_len,
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             r[0], r[1], r[2], r[3],
             r[4], r[5],
             r[6], r[7],
             r[8], r[9],
             r[10], r[11], r[12], r[13], r[14], r[15]);
             
    return 0;
}

ErasecureError carve_state_create(CarveState *cs, const char *file_type, uint64_t start_block) {
    if (!cs || !file_type) return ERASECURE_ERR_INVALID_ARG;
    
    memset(cs, 0, sizeof(CarveState));
    
    ErasecureError err = generate_uuid(cs->uuid, sizeof(cs->uuid));
    if (err != 0) return err;
    
    strncpy(cs->file_type, file_type, sizeof(cs->file_type) - 1);
    cs->start_block = start_block;
    cs->status = CANDIDATE_STATUS_NEW;
    cs->validation = VALIDATION_RESULT_UNKNOWN;
    
    return blockvector_create(&cs->blockvector, 16);
}

void carve_state_free(CarveState *cs) {
    if (cs) {
        blockvector_free(&cs->blockvector);
        if (cs->format_state) {
            free(cs->format_state);
        }
        memset(cs, 0, sizeof(CarveState));
    }
}

ErasecureError carve_state_set_format_state(CarveState *cs, const void *data, size_t len) {
    if (!cs || (!data && len > 0)) return ERASECURE_ERR_INVALID_ARG;
    
    if (cs->format_state) {
        free(cs->format_state);
        cs->format_state = NULL;
    }
    
    cs->format_state_len = len;
    if (len > 0) {
        cs->format_state = malloc(len);
        if (!cs->format_state) return ERASECURE_ERR_NO_MEM;
        memcpy(cs->format_state, data, len);
    }
    return 0;
}

const char *candidate_status_str(CandidateStatus status) {
    switch (status) {
        case CANDIDATE_STATUS_NEW: return "NEW";
        case CANDIDATE_STATUS_SCANNING: return "SCANNING";
        case CANDIDATE_STATUS_PROMISING: return "PROMISING";
        case CANDIDATE_STATUS_VALIDATING: return "VALIDATING";
        case CANDIDATE_STATUS_VALIDATED: return "VALIDATED";
        case CANDIDATE_STATUS_FAILED: return "FAILED";
        case CANDIDATE_STATUS_CANCELLED: return "CANCELLED";
        default: return "UNKNOWN";
    }
}

const char *validation_result_str(ValidationResult result) {
    switch (result) {
        case VALIDATION_RESULT_UNKNOWN: return "UNKNOWN";
        case VALIDATION_RESULT_PROMISING: return "PROMISING";
        case VALIDATION_RESULT_VALIDATES_TO: return "VALIDATES_TO";
        case VALIDATION_RESULT_VALIDATES: return "VALIDATES";
        case VALIDATION_RESULT_INVALID: return "INVALID";
        default: return "UNKNOWN";
    }
}
