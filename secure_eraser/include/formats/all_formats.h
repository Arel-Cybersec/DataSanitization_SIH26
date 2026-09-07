#ifndef ERASECURE_ALL_FORMATS_H
#define ERASECURE_ALL_FORMATS_H

#include "common/error.h"
#include "recovery/file_type_registry.h"

#include "formats/jpeg_validator.h"
#include "formats/png_validator.h"
#include "formats/pdf_validator.h"
#include "formats/zip_validator.h"
#include "formats/gif_validator.h"
#include "formats/mp3_validator.h"
#include "formats/elf_validator.h"

/**
 * @brief Registers all supported file format validators with the provided registry.
 */
ErasecureError register_all_validators(FileTypeRegistry *reg);

#endif // ERASECURE_ALL_FORMATS_H
