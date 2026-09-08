#ifndef ERASECURE_NVME_SANITIZE_H
#define ERASECURE_NVME_SANITIZE_H

#include <stdbool.h>
#include "common/error.h"

typedef enum {
    NVME_SANITIZE_SUCCESS         = 0,
    NVME_SANITIZE_NOT_SUPPORTED   = 1,
    NVME_SANITIZE_FAILED          = 2,
    NVME_SANITIZE_NOT_IMPLEMENTED = 3,
} NvmeSanitizeStatus;

typedef struct {
    bool can_format_nvm;           /* Format NVM supported */
    bool can_format_crypto_erase;  /* Format with SES=2 (Crypto Erase) */
    bool can_sanitize_block;       /* Sanitize Block Erase */
    bool can_sanitize_overwrite;   /* Sanitize Overwrite */
    bool can_sanitize_crypto;      /* Sanitize Crypto Erase */
    bool format_all_ns;            /* Format applies to all namespaces */
} NvmeSanitizeCapabilities;

/**
 * @brief Queries NVMe sanitize capabilities for a specified device.
 * Does NOT execute any destructive commands - query only.
 *
 * @param device_path Path to the NVMe device
 * @param caps Pointer to structure to store capabilities
 * @return ErasecureError success or failure code
 */
ErasecureError nvme_sanitize_query(const char *device_path, NvmeSanitizeCapabilities *caps);

/**
 * @brief Returns a string representation of the NVMe sanitize status.
 *
 * @param status The sanitize status enum
 * @return const char* String representation of the status
 */
const char *nvme_sanitize_status_str(NvmeSanitizeStatus status);

#endif // ERASECURE_NVME_SANITIZE_H
