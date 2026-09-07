#ifndef ERASECURE_ATA_SANITIZE_H
#define ERASECURE_ATA_SANITIZE_H

#include <stdint.h>
#include <stdbool.h>
#include "common/error.h"
#include "common/types.h"

typedef enum {
    ATA_SANITIZE_SUCCESS        = 0,
    ATA_SANITIZE_NOT_SUPPORTED  = 1,
    ATA_SANITIZE_FROZEN         = 2,
    ATA_SANITIZE_LOCKED         = 3,
    ATA_SANITIZE_FAILED         = 4,
    ATA_SANITIZE_NOT_IMPLEMENTED = 5,
} AtaSanitizeStatus;

typedef struct {
    bool can_security_erase;       /* ATA SECURITY ERASE UNIT available */
    bool can_enhanced_erase;       /* Enhanced erase available */
    bool can_sanitize_overwrite;   /* SANITIZE overwrite */
    bool can_sanitize_block_erase; /* SANITIZE block erase */
    bool can_sanitize_crypto;      /* SANITIZE crypto scramble */
    bool is_frozen;                /* Security frozen (cannot erase) */
    bool is_locked;
    uint16_t normal_erase_minutes;
    uint16_t enhanced_erase_minutes;
} AtaSanitizeCapabilities;

/**
 * @brief Queries the sanitization capabilities of a block device.
 * @param device_path Path to the block device.
 * @param caps Pointer to the capabilities structure to be populated.
 * @return ERASECURE_SUCCESS on success, or an appropriate error code.
 */
ErasecureError ata_sanitize_query(const char *device_path, AtaSanitizeCapabilities *caps);

/**
 * @brief Converts an ATA sanitize status to a human-readable string.
 * @param status The status enum value.
 * @return A string representation of the status.
 */
const char *ata_sanitize_status_str(AtaSanitizeStatus status);

#endif /* ERASECURE_ATA_SANITIZE_H */
