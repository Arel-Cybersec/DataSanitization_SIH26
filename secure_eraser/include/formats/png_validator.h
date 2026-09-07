#ifndef ERASECURE_PNG_VALIDATOR_H
#define ERASECURE_PNG_VALIDATOR_H

#include "common/error.h"
#include "common/types.h"
#include "recovery/validator.h"
#include "recovery/file_type_registry.h"

/**
 * @brief Block validator for PNG format.
 */
uint32_t png_block_validator(const uint8_t *block, size_t size);

/**
 * @brief File validator for PNG format.
 */
FileValidationResult png_file_validator(const uint8_t *file_data, size_t size, size_t *parsed_size);

/**
 * @brief Registers PNG validators with the registry.
 */
ErasecureError png_validator_register(FileTypeRegistry *reg);

#endif // ERASECURE_PNG_VALIDATOR_H
