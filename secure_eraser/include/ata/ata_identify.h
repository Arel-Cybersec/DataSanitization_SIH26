#ifndef ERASECURE_ATA_IDENTIFY_H
#define ERASECURE_ATA_IDENTIFY_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "common/error.h"
#include "common/types.h"

/* ATA IDENTIFY DEVICE data (selected fields) */
typedef struct {
    char     model[41];                /* words 27-46, ASCII */
    char     serial[21];               /* words 10-19, ASCII */
    char     firmware[9];              /* words 23-26, ASCII */
    uint64_t lba_capacity;             /* words 100-103 (48-bit LBA) */
    uint32_t logical_sector_size;      /* word 117-118 if bit 12 of word 106 set */
    uint32_t physical_sector_size;
    
    /* Security feature set (word 82, bit 1; word 85, bit 1; word 128-129) */
    bool     security_supported;       /* word 82 bit 1 */
    bool     security_enabled;         /* word 85 bit 1 */
    bool     security_locked;          /* word 128 bit 2 */
    bool     security_frozen;          /* word 128 bit 3 */
    bool     security_count_expired;   /* word 128 bit 4 */
    bool     enhanced_erase_supported; /* word 128 bit 5 */
    uint16_t erase_time_normal;        /* word 89: time for normal erase (minutes), 0=not reported */
    uint16_t erase_time_enhanced;      /* word 90: time for enhanced erase (minutes) */
    
    /* Sanitize feature set (word 59) */
    bool     sanitize_supported;       /* word 59 bit 12 */
    bool     sanitize_crypto_scramble; /* word 59 bit 13 */
    bool     sanitize_block_erase;     /* word 59 bit 14 */
    bool     sanitize_overwrite;       /* word 59 bit 15 */
    
    /* Raw identify data for future use */
    uint16_t raw_words[256];
} AtaIdentifyData;

/**
 * @brief Retrieves the ATA IDENTIFY DEVICE data for a block device.
 * @param device_path Path to the block device.
 * @param data Pointer to the structure to be populated.
 * @return ERASECURE_SUCCESS on success, or an appropriate error code.
 */
ErasecureError ata_identify_device(const char *device_path, AtaIdentifyData *data);

/**
 * @brief Generates a human-readable summary of the IDENTIFY data.
 * @param data The populated AtaIdentifyData structure.
 * @param buf Buffer to write the string into.
 * @param buf_len Size of the buffer.
 * @return Pointer to the buffer.
 */
const char *ata_identify_summary(const AtaIdentifyData *data, char *buf, size_t buf_len);

#endif /* ERASECURE_ATA_IDENTIFY_H */
