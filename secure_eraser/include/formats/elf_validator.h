#ifndef ERASECURE_ELF_VALIDATOR_H
#define ERASECURE_ELF_VALIDATOR_H

#include "common/error.h"
#include "common/types.h"
#include "recovery/validator.h"
#include "recovery/file_type_registry.h"

/**
 * @brief Block validator for ELF format.
 */
uint32_t elf_block_validator(const uint8_t *block, size_t size);

/**
 * @brief File validator for ELF format.
 */
FileValidationResult elf_file_validator(const uint8_t *file_data, size_t size, size_t *parsed_size);

/**
 * @brief Registers ELF validators with the registry.
 */
ErasecureError elf_validator_register(FileTypeRegistry *reg);

#endif // ERASECURE_ELF_VALIDATOR_H
