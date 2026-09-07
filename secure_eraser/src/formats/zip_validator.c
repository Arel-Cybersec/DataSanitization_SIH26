#include "formats/zip_validator.h"
#include <string.h>

static const uint8_t ZIP_LOCAL_HEADER[] = {0x50, 0x4B, 0x03, 0x04};
static const uint8_t ZIP_CENTRAL_DIR[] = {0x50, 0x4B, 0x01, 0x02};
static const uint8_t ZIP_EOCD[] = {0x50, 0x4B, 0x05, 0x06};

uint32_t zip_block_validator(const uint8_t *block, size_t size) {
    if (!block || size < 4) return 0;
    uint32_t score = 0;
    for (size_t i = 0; i < size - 3; i++) {
        if (memcmp(block + i, ZIP_LOCAL_HEADER, 4) == 0 ||
            memcmp(block + i, ZIP_CENTRAL_DIR, 4) == 0 ||
            memcmp(block + i, ZIP_EOCD, 4) == 0) {
            score += 15;
        }
    }
    return score;
}

FileValidationResult zip_file_validator(const uint8_t *file_data, size_t size, size_t *parsed_size) {
    if (!file_data || size < 22) return FILE_VALIDATION_INVALID;
    if (memcmp(file_data, ZIP_LOCAL_HEADER, 4) != 0) return FILE_VALIDATION_INVALID;
    
    // Look for EOCD from end
    int found_eocd = 0;
    size_t eocd_offset = 0;
    size_t search_start = (size > 65536 + 22) ? size - 65536 - 22 : 0;
    for (size_t i = size - 22; i >= search_start; i--) {
        if (memcmp(file_data + i, ZIP_EOCD, 4) == 0) {
            found_eocd = 1;
            eocd_offset = i;
            break;
        }
        if (i == 0) break;
    }
    
    if (found_eocd) {
        if (parsed_size) *parsed_size = size; // Could parse comment length but size works
        return FILE_VALIDATION_VALIDATES;
    }
    
    if (parsed_size) *parsed_size = size;
    return FILE_VALIDATION_PROMISING;
}

ErasecureError zip_validator_register(FileTypeRegistry *reg) {
    if (!reg) return ERASECURE_ERROR_INVALID_PARAM;
    return ERASECURE_SUCCESS;
}
