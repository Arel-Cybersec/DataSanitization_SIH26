#ifndef ERASECURE_ZIP_VALIDATOR_H
#define ERASECURE_ZIP_VALIDATOR_H

#include "common/error.h"
#include "common/types.h"
#include "recovery/validator.h"
#include "recovery/file_type_registry.h"

/**
 * @brief Block validator for ZIP format.
 */
uint32_t zip_block_validator(const uint8_t *block, size_t size);

/**
 * @brief File validator for ZIP format.
 */
FileValidationResult zip_file_validator(const uint8_t *file_data, size_t size, size_t *parsed_size);

/**
 * @brief Registers ZIP validators with the registry.
 */
ErasecureError zip_validator_register(FileTypeRegistry *reg);

#endif // ERASECURE_ZIP_VALIDATOR_H
