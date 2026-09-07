#ifndef ERASECURE_FILE_TYPE_REGISTRY_H
#define ERASECURE_FILE_TYPE_REGISTRY_H

#include "common/types.h"
#include "common/error.h"
#include "recovery/validator.h"
#include "recovery/discovery.h"
#include <stdint.h>
#include <stdbool.h>

struct FileTypeDescriptor {
    char        name[32];          /* e.g. "JPEG", "PNG" */
    char        extension[16];     /* e.g. "jpg", "png" */
    char        mime_type[64];     /* e.g. "image/jpeg" */
    char        category[32];      /* e.g. "Image", "Document" */
    uint64_t    min_size;          /* Minimum expected file size */
    uint64_t    max_size;          /* Maximum expected file size (0 = unlimited) */
    /* Header/footer signatures */
    SignaturePattern *headers;
    size_t           header_count;
    SignaturePattern *footers;
    size_t           footer_count;
    /* Search direction: 1 = forward, -1 = backward */
    int         search_direction;
    /* Validator callbacks (may be NULL) */
    BlockValidatorFn    block_validator;
    FileValidatorFn     file_validator;
    /* Feature flags */
    bool        fragmented_recovery_enabled;
    bool        enabled;           /* Can be disabled at runtime */
};

typedef struct {
    FileTypeDescriptor *types;
    size_t              count;
    size_t              capacity;
} FileTypeRegistry;

ErasecureError file_type_registry_init(FileTypeRegistry *reg);
void file_type_registry_destroy(FileTypeRegistry *reg);
ErasecureError file_type_registry_register(FileTypeRegistry *reg, const FileTypeDescriptor *desc);
const FileTypeDescriptor *file_type_registry_find(const FileTypeRegistry *reg, const char *name);
size_t file_type_registry_count(const FileTypeRegistry *reg);
const FileTypeDescriptor *file_type_registry_get(const FileTypeRegistry *reg, size_t index);

/* Register all built-in file types (JPEG, PNG, PDF, ZIP, GIF, MP3, ELF) */
ErasecureError file_type_registry_register_defaults(FileTypeRegistry *reg);

#endif
