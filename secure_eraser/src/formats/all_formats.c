#include "formats/all_formats.h"

ErasecureError register_all_validators(FileTypeRegistry *reg) {
    if (!reg) return ERASECURE_ERROR_INVALID_PARAM;
    
    jpeg_validator_register(reg);
    png_validator_register(reg);
    pdf_validator_register(reg);
    zip_validator_register(reg);
    gif_validator_register(reg);
    mp3_validator_register(reg);
    elf_validator_register(reg);
    
    return ERASECURE_SUCCESS;
}
