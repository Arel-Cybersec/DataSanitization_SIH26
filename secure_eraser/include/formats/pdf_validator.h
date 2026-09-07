#ifndef ERASECURE_PDF_VALIDATOR_H
#define ERASECURE_PDF_VALIDATOR_H

#include "common/error.h"
#include "common/types.h"
#include "recovery/validator.h"
#include "recovery/file_type_registry.h"

/**
 * @brief Block validator for PDF format.
 */
uint32_t pdf_block_validator(const uint8_t *block, size_t size);

/**
 * @brief File validator for PDF format.
 */
FileValidationResult pdf_file_validator(const uint8_t *file_data, size_t size, size_t *parsed_size);

/**
 * @brief Registers PDF validators with the registry.
 */
ErasecureError pdf_validator_register(FileTypeRegistry *reg);

#endif // ERASECURE_PDF_VALIDATOR_H
