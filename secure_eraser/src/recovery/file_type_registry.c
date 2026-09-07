#include "recovery/file_type_registry.h"
#include <stdlib.h>
#include <string.h>

/**
 * @brief Initialize the file type registry.
 */
ErasecureError file_type_registry_init(FileTypeRegistry *reg) {
    if (!reg) return ERASECURE_ERROR_INVALID_ARGUMENT;
    reg->count = 0;
    reg->capacity = 16;
    reg->types = calloc(reg->capacity, sizeof(FileTypeDescriptor));
    if (!reg->types) return ERASECURE_ERROR_MEMORY;
    return ERASECURE_SUCCESS;
}

/**
 * @brief Destroy the file type registry and free patterns.
 */
void file_type_registry_destroy(FileTypeRegistry *reg) {
    if (!reg) return;
    for (size_t i = 0; i < reg->count; i++) {
        FileTypeDescriptor *desc = &reg->types[i];
        if (desc->headers) {
            for (size_t j = 0; j < desc->header_count; j++) {
                free((void*)desc->headers[j].bytes);
                free((void*)desc->headers[j].type_name);
            }
            free(desc->headers);
        }
        if (desc->footers) {
            for (size_t j = 0; j < desc->footer_count; j++) {
                free((void*)desc->footers[j].bytes);
                free((void*)desc->footers[j].type_name);
            }
            free(desc->footers);
        }
    }
    free(reg->types);
    memset(reg, 0, sizeof(*reg));
}

/**
 * @brief Deep copy signatures.
 */
static SignaturePattern *copy_signatures(const SignaturePattern *src, size_t count) {
    if (!src || count == 0) return NULL;
    SignaturePattern *dst = calloc(count, sizeof(SignaturePattern));
    if (!dst) return NULL;
    for (size_t i = 0; i < count; i++) {
        dst[i].length = src[i].length;
        dst[i].offset = src[i].offset;
        dst[i].is_footer = src[i].is_footer;
        
        uint8_t *b = malloc(src[i].length);
        if (b) {
            memcpy(b, src[i].bytes, src[i].length);
            dst[i].bytes = b;
        }
        dst[i].type_name = src[i].type_name ? strdup(src[i].type_name) : NULL;
    }
    return dst;
}

/**
 * @brief Register a new file type descriptor.
 */
ErasecureError file_type_registry_register(FileTypeRegistry *reg, const FileTypeDescriptor *desc) {
    if (!reg || !desc) return ERASECURE_ERROR_INVALID_ARGUMENT;
    if (reg->count >= reg->capacity) {
        size_t new_cap = reg->capacity * 2;
        FileTypeDescriptor *new_types = realloc(reg->types, new_cap * sizeof(FileTypeDescriptor));
        if (!new_types) return ERASECURE_ERROR_MEMORY;
        reg->types = new_types;
        reg->capacity = new_cap;
    }
    
    FileTypeDescriptor *dest = &reg->types[reg->count];
    memcpy(dest, desc, sizeof(FileTypeDescriptor));
    
    // Deep copy arrays
    dest->headers = copy_signatures(desc->headers, desc->header_count);
    dest->footers = copy_signatures(desc->footers, desc->footer_count);
    
    reg->count++;
    return ERASECURE_SUCCESS;
}

/**
 * @brief Find a file type descriptor by name (case insensitive).
 */
const FileTypeDescriptor *file_type_registry_find(const FileTypeRegistry *reg, const char *name) {
    if (!reg || !name) return NULL;
    for (size_t i = 0; i < reg->count; i++) {
#ifdef _WIN32
        if (_stricmp(reg->types[i].name, name) == 0) return &reg->types[i];
#else
        if (strcasecmp(reg->types[i].name, name) == 0) return &reg->types[i];
#endif
    }
    return NULL;
}

/**
 * @brief Get the count of registered descriptors.
 */
size_t file_type_registry_count(const FileTypeRegistry *reg) {
    return reg ? reg->count : 0;
}

/**
 * @brief Get descriptor by index.
 */
const FileTypeDescriptor *file_type_registry_get(const FileTypeRegistry *reg, size_t index) {
    if (!reg || index >= reg->count) return NULL;
    return &reg->types[index];
}

/**
 * @brief Register default built-in file types.
 */
ErasecureError file_type_registry_register_defaults(FileTypeRegistry *reg) {
    if (!reg) return ERASECURE_ERROR_INVALID_ARGUMENT;
    
    // Stub examples - a real implementation would define valid bytes.
    const uint8_t jpeg_magic[] = {0xFF, 0xD8, 0xFF};
    SignaturePattern jpeg_header = {jpeg_magic, 3, 0, false, "JPEG"};
    FileTypeDescriptor jpeg = {
        .name = "JPEG",
        .extension = "jpg",
        .mime_type = "image/jpeg",
        .category = "Image",
        .min_size = 128,
        .max_size = 100 * 1024 * 1024,
        .headers = &jpeg_header,
        .header_count = 1,
        .footers = NULL,
        .footer_count = 0,
        .search_direction = 1,
        .block_validator = NULL,
        .file_validator = NULL,
        .fragmented_recovery_enabled = true,
        .enabled = true
    };
    file_type_registry_register(reg, &jpeg);

    const uint8_t png_magic[] = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
    SignaturePattern png_header = {png_magic, 8, 0, false, "PNG"};
    FileTypeDescriptor png = {
        .name = "PNG",
        .extension = "png",
        .mime_type = "image/png",
        .category = "Image",
        .min_size = 64,
        .max_size = 100 * 1024 * 1024,
        .headers = &png_header,
        .header_count = 1,
        .footers = NULL,
        .footer_count = 0,
        .search_direction = 1,
        .block_validator = NULL,
        .file_validator = NULL,
        .fragmented_recovery_enabled = true,
        .enabled = true
    };
    file_type_registry_register(reg, &png);

    const uint8_t pdf_magic[] = {0x25, 0x50, 0x44, 0x46, 0x2D};
    SignaturePattern pdf_header = {pdf_magic, 5, 0, false, "PDF"};
    FileTypeDescriptor pdf = {
        .name = "PDF",
        .extension = "pdf",
        .mime_type = "application/pdf",
        .category = "Document",
        .min_size = 64,
        .max_size = 0,
        .headers = &pdf_header,
        .header_count = 1,
        .footers = NULL,
        .footer_count = 0,
        .search_direction = 1,
        .block_validator = NULL,
        .file_validator = NULL,
        .fragmented_recovery_enabled = true,
        .enabled = true
    };
    file_type_registry_register(reg, &pdf);

    const uint8_t zip_magic[] = {0x50, 0x4B, 0x03, 0x04};
    SignaturePattern zip_header = {zip_magic, 4, 0, false, "ZIP"};
    FileTypeDescriptor zip = {
        .name = "ZIP",
        .extension = "zip",
        .mime_type = "application/zip",
        .category = "Archive",
        .min_size = 22,
        .max_size = 0,
        .headers = &zip_header,
        .header_count = 1,
        .footers = NULL,
        .footer_count = 0,
        .search_direction = 1,
        .block_validator = NULL,
        .file_validator = NULL,
        .fragmented_recovery_enabled = true,
        .enabled = true
    };
    file_type_registry_register(reg, &zip);

    const uint8_t gif_magic[] = {0x47, 0x49, 0x46, 0x38, 0x39, 0x61};
    SignaturePattern gif_header = {gif_magic, 6, 0, false, "GIF"};
    FileTypeDescriptor gif = {
        .name = "GIF",
        .extension = "gif",
        .mime_type = "image/gif",
        .category = "Image",
        .min_size = 32,
        .max_size = 50 * 1024 * 1024,
        .headers = &gif_header,
        .header_count = 1,
        .footers = NULL,
        .footer_count = 0,
        .search_direction = 1,
        .block_validator = NULL,
        .file_validator = NULL,
        .fragmented_recovery_enabled = true,
        .enabled = true
    };
    file_type_registry_register(reg, &gif);

    const uint8_t mp3_magic[] = {0xFF, 0xFB};
    SignaturePattern mp3_header = {mp3_magic, 2, 0, false, "MP3"};
    FileTypeDescriptor mp3 = {
        .name = "MP3",
        .extension = "mp3",
        .mime_type = "audio/mpeg",
        .category = "Audio",
        .min_size = 128,
        .max_size = 100 * 1024 * 1024,
        .headers = &mp3_header,
        .header_count = 1,
        .footers = NULL,
        .footer_count = 0,
        .search_direction = 1,
        .block_validator = NULL,
        .file_validator = NULL,
        .fragmented_recovery_enabled = true,
        .enabled = true
    };
    file_type_registry_register(reg, &mp3);

    const uint8_t elf_magic[] = {0x7F, 0x45, 0x4C, 0x46};
    SignaturePattern elf_header = {elf_magic, 4, 0, false, "ELF"};
    FileTypeDescriptor elf = {
        .name = "ELF",
        .extension = "elf",
        .mime_type = "application/x-executable",
        .category = "Executable",
        .min_size = 52,
        .max_size = 0,
        .headers = &elf_header,
        .header_count = 1,
        .footers = NULL,
        .footer_count = 0,
        .search_direction = 1,
        .block_validator = NULL,
        .file_validator = NULL,
        .fragmented_recovery_enabled = true,
        .enabled = true
    };
    file_type_registry_register(reg, &elf);

    return ERASECURE_SUCCESS;
}
