#include "formats/png_validator.h"
#include <string.h>
#include <zlib.h> // For crc32

static const uint8_t PNG_MAGIC[8] = {0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n'};

uint32_t png_block_validator(const uint8_t *block, size_t size) {
    if (!block || size < 4) return 0;
    uint32_t score = 0;
    for (size_t i = 0; i < size - 3; i++) {
        if (memcmp(block + i, "IHDR", 4) == 0 || memcmp(block + i, "IDAT", 4) == 0 ||
            memcmp(block + i, "PLTE", 4) == 0 || memcmp(block + i, "IEND", 4) == 0) {
            score += 20;
        }
    }
    return score;
}

FileValidationResult png_file_validator(const uint8_t *file_data, size_t size, size_t *parsed_size) {
    if (!file_data || size < 8) return FILE_VALIDATION_INVALID;
    if (memcmp(file_data, PNG_MAGIC, 8) != 0) return FILE_VALIDATION_INVALID;
    
    size_t offset = 8;
    int has_ihdr = 0;
    
    while (offset + 12 <= size) {
        uint32_t length = (file_data[offset] << 24) | (file_data[offset+1] << 16) | (file_data[offset+2] << 8) | file_data[offset+3];
        if (offset + 12 + length > size) break;
        
        uint32_t computed_crc = crc32(0, file_data + offset + 4, length + 4);
        uint32_t stored_crc = (file_data[offset + 8 + length] << 24) | (file_data[offset + 9 + length] << 16) | 
                              (file_data[offset + 10 + length] << 8) | file_data[offset + 11 + length];
        
        if (computed_crc != stored_crc) return FILE_VALIDATION_INVALID;
        
        if (memcmp(file_data + offset + 4, "IHDR", 4) == 0) {
            if (offset != 8 || length != 13) return FILE_VALIDATION_INVALID;
            has_ihdr = 1;
        } else if (memcmp(file_data + offset + 4, "IEND", 4) == 0) {
            if (parsed_size) *parsed_size = offset + 12;
            return has_ihdr ? FILE_VALIDATION_VALIDATES : FILE_VALIDATION_INVALID;
        }
        
        offset += 12 + length;
    }
    if (parsed_size) *parsed_size = offset;
    return has_ihdr ? FILE_VALIDATION_PROMISING : FILE_VALIDATION_INVALID;
}

ErasecureError png_validator_register(FileTypeRegistry *reg) {
    if (!reg) return ERASECURE_ERROR_INVALID_PARAM;
    return ERASECURE_SUCCESS;
}
