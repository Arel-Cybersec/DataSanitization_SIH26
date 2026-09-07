#include "ata/ata_sanitize.h"
#include "ata/ata_identify.h"
#include <stddef.h>
#include <string.h>

ErasecureError ata_sanitize_query(const char *device_path, AtaSanitizeCapabilities *caps) {
    if (!device_path || !caps) {
        return ERASECURE_ERR_INVALID_ARGUMENT;
    }

    memset(caps, 0, sizeof(AtaSanitizeCapabilities));

    AtaIdentifyData id_data;
    ErasecureError err = ata_identify_device(device_path, &id_data);
    if (err != ERASECURE_SUCCESS) {
        return err;
    }

    caps->is_frozen = id_data.security_frozen;
    caps->is_locked = id_data.security_locked;
    
    caps->can_security_erase = id_data.security_supported && !id_data.security_frozen;
    caps->can_enhanced_erase = caps->can_security_erase && id_data.enhanced_erase_supported;
    
    caps->can_sanitize_overwrite = id_data.sanitize_supported && id_data.sanitize_overwrite;
    caps->can_sanitize_block_erase = id_data.sanitize_supported && id_data.sanitize_block_erase;
    caps->can_sanitize_crypto = id_data.sanitize_supported && id_data.sanitize_crypto_scramble;
    
    caps->normal_erase_minutes = id_data.erase_time_normal;
    caps->enhanced_erase_minutes = id_data.erase_time_enhanced;

    return ERASECURE_SUCCESS;
}

const char *ata_sanitize_status_str(AtaSanitizeStatus status) {
    switch (status) {
        case ATA_SANITIZE_SUCCESS:
            return "SUCCESS";
        case ATA_SANITIZE_NOT_SUPPORTED:
            return "NOT SUPPORTED";
        case ATA_SANITIZE_FROZEN:
            return "FROZEN";
        case ATA_SANITIZE_LOCKED:
            return "LOCKED";
        case ATA_SANITIZE_FAILED:
            return "FAILED";
        case ATA_SANITIZE_NOT_IMPLEMENTED:
            return "NOT IMPLEMENTED";
        default:
            return "UNKNOWN";
    }
}
