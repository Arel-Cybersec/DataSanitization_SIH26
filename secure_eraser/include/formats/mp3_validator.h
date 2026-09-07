#ifndef ERASECURE_MP3_VALIDATOR_H
#define ERASECURE_MP3_VALIDATOR_H

#include "common/error.h"
#include "common/types.h"
#include "recovery/validator.h"
#include "recovery/file_type_registry.h"

/**
 * @brief Block validator for MP3 format.
 */
uint32_t mp3_block_validator(const uint8_t *block, size_t size);

/**
 * @brief File validator for MP3 format.
 */
FileValidationResult mp3_file_validator(const uint8_t *file_data, size_t size, size_t *parsed_size);

/**
 * @brief Registers MP3 validators with the registry.
 */
ErasecureError mp3_validator_register(FileTypeRegistry *reg);

#endif // ERASECURE_MP3_VALIDATOR_H
