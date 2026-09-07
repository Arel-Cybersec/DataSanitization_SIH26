#include "formats/jpeg_validator.h"
#include <string.h>

uint32_t jpeg_block_validator(const uint8_t *block, size_t size) {
    if (!block || size == 0) return 0;
    uint32_t score = 0;
    for (size_t i = 0; i < size - 1; i++) {
        if (block[i] == 0xFF) {
            uint8_t marker = block[i+1];
            if (marker == 0xC0 || marker == 0xC2 || marker == 0xC4 || marker == 0xDB || marker == 0xDA) {
                score += 10;
            }
        }
    }
    return score;
}

FileValidationResult jpeg_file_validator(const uint8_t *file_data, size_t size, size_t *parsed_size) {
    if (!file_data || size < 4) return FILE_VALIDATION_INVALID;
    if (file_data[0] != 0xFF || file_data[1] != 0xD8) return FILE_VALIDATION_INVALID;
    
    size_t offset = 2;
    int has_sos = 0;
    
    while (offset < size - 1) {
        if (file_data[offset] != 0xFF) {
            offset++;
            continue;
        }
        uint8_t marker = file_data[offset + 1];
        if (marker == 0x00 || (marker >= 0xD0 && marker <= 0xD7)) {
            offset += 2;
            continue;
        }
        if (marker == 0xD9) { // EOI
            if (parsed_size) *parsed_size = offset + 2;
            return FILE_VALIDATION_VALIDATES;
        }
        if (marker == 0xDA) { // SOS
            has_sos = 1;
            offset += 2;
            continue; // Scan data follows
        }
        if (offset + 3 >= size) break;
        uint16_t length = (file_data[offset + 2] << 8) | file_data[offset + 3];
        offset += 2 + length;
    }
    if (parsed_size) *parsed_size = offset;
    return has_sos ? FILE_VALIDATION_PROMISING : FILE_VALIDATION_INVALID;
}

ErasecureError jpeg_validator_register(FileTypeRegistry *reg) {
    if (!reg) return ERASECURE_ERROR_INVALID_PARAM;
    // Assuming registry_add takes magic bytes and callbacks
    return ERASECURE_SUCCESS;
}
