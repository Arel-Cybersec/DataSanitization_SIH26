#ifndef ERASECURE_GIF_VALIDATOR_H
#define ERASECURE_GIF_VALIDATOR_H

#include "common/error.h"
#include "common/types.h"
#include "recovery/validator.h"
#include "recovery/file_type_registry.h"

/**
 * @brief Block validator for GIF format.
 */
uint32_t gif_block_validator(const uint8_t *block, size_t size);

/**
 * @brief File validator for GIF format.
 */
FileValidationResult gif_file_validator(const uint8_t *file_data, size_t size, size_t *parsed_size);

/**
 * @brief Registers GIF validators with the registry.
 */
ErasecureError gif_validator_register(FileTypeRegistry *reg);

#endif // ERASECURE_GIF_VALIDATOR_H
