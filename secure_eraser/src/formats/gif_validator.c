#include "formats/gif_validator.h"
#include <string.h>

uint32_t gif_block_validator(const uint8_t *block, size_t size) {
    if (!block || size < 6) return 0;
    if (memcmp(block, "GIF87a", 6) == 0 || memcmp(block, "GIF89a", 6) == 0) {
        return 100;
    }
    return 0;
}

FileValidationResult gif_file_validator(const uint8_t *file_data, size_t size, size_t *parsed_size) {
    if (!file_data || size < 14) return FILE_VALIDATION_INVALID;
    if (memcmp(file_data, "GIF87a", 6) != 0 && memcmp(file_data, "GIF89a", 6) != 0) {
        return FILE_VALIDATION_INVALID;
    }
    
    size_t offset = 13;
    uint8_t packed = file_data[10];
    if (packed & 0x80) { // Global Color Table Flag
        int gct_size = 3 * (1 << ((packed & 0x07) + 1));
        offset += gct_size;
    }
    
    while (offset < size) {
        if (file_data[offset] == 0x3B) { // Trailer
            if (parsed_size) *parsed_size = offset + 1;
            return FILE_VALIDATION_VALIDATES;
        }
        
        if (file_data[offset] == 0x2C) { // Image Descriptor
            if (offset + 10 > size) break;
            offset += 10;
            uint8_t img_packed = file_data[offset - 1];
            if (img_packed & 0x80) { // Local Color Table
                int lct_size = 3 * (1 << ((img_packed & 0x07) + 1));
                offset += lct_size;
            }
            if (offset >= size) break;
            offset++; // LZW Minimum Code Size
            while (offset < size && file_data[offset] != 0) {
                offset += 1 + file_data[offset];
            }
            offset++; // Block Terminator
        } else if (file_data[offset] == 0x21) { // Extension
            if (offset + 2 > size) break;
            offset += 2;
            while (offset < size && file_data[offset] != 0) {
                offset += 1 + file_data[offset];
            }
            offset++;
        } else {
            break; // Unknown or invalid
        }
    }
    
    if (parsed_size) *parsed_size = offset;
    return FILE_VALIDATION_PROMISING;
}

ErasecureError gif_validator_register(FileTypeRegistry *reg) {
    if (!reg) return ERASECURE_ERROR_INVALID_PARAM;
    return ERASECURE_SUCCESS;
}
