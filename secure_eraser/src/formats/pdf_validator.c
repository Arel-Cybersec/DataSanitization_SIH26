#include "formats/pdf_validator.h"
#include <string.h>

static const char* PDF_MAGIC = "%PDF-";
static const char* PDF_EOF = "%%EOF";

uint32_t pdf_block_validator(const uint8_t *block, size_t size) {
    if (!block || size == 0) return 0;
    uint32_t score = 0;
    const char *keywords[] = {"obj", "endobj", "stream", "endstream", "xref", "trailer", "startxref"};
    
    // Very simple string matching logic for block validator
    for (size_t i = 0; i < sizeof(keywords)/sizeof(keywords[0]); i++) {
        size_t len = strlen(keywords[i]);
        for (size_t j = 0; j + len <= size; j++) {
            if (memcmp(block + j, keywords[i], len) == 0) {
                score += 5;
                j += len; // Skip word
            }
        }
    }
    return score;
}

FileValidationResult pdf_file_validator(const uint8_t *file_data, size_t size, size_t *parsed_size) {
    if (!file_data || size < 5) return FILE_VALIDATION_INVALID;
    if (memcmp(file_data, PDF_MAGIC, 5) != 0) return FILE_VALIDATION_INVALID;
    
    int found_eof = 0;
    size_t search_start = (size > 1024) ? (size - 1024) : 0;
    for (size_t i = search_start; i + 5 <= size; i++) {
        if (memcmp(file_data + i, PDF_EOF, 5) == 0) {
            found_eof = 1;
            if (parsed_size) *parsed_size = i + 5;
            break;
        }
    }
    
    if (found_eof) {
        return FILE_VALIDATION_VALIDATES;
    }
    
    if (parsed_size) *parsed_size = size;
    return FILE_VALIDATION_PROMISING;
}

ErasecureError pdf_validator_register(FileTypeRegistry *reg) {
    if (!reg) return ERASECURE_ERROR_INVALID_PARAM;
    return ERASECURE_SUCCESS;
}
