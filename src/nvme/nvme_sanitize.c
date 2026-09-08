#include "nvme/nvme_sanitize.h"
#include "nvme/nvme_identify.h"
#include <stddef.h>

ErasecureError nvme_sanitize_query(const char *device_path, NvmeSanitizeCapabilities *caps) {
    if (!device_path || !caps) return ERASECURE_ERR_INVALID_ARGUMENT;

    NvmeControllerData ctrl;
    ErasecureError err = nvme_identify_controller(device_path, &ctrl);
    if (err != ERASECURE_SUCCESS) return err;

    caps->can_format_nvm = ctrl.format_supported;
    caps->can_format_crypto_erase = false;
    
    // Crypto erase via format: Format NVM Crypto Erase bit (bit 2) of FNA
    if (caps->can_format_nvm && (ctrl.fna & (1 << 2))) {
        caps->can_format_crypto_erase = true;
    }

    // Format applies to all namespaces if FNA bit 0 is set
    caps->format_all_ns = (ctrl.fna & (1 << 0)) != 0;

    caps->can_sanitize_block = ctrl.sanitize_block;
    caps->can_sanitize_overwrite = ctrl.sanitize_overwrite;
    caps->can_sanitize_crypto = ctrl.sanitize_crypto;

    return ERASECURE_SUCCESS;
}

const char *nvme_sanitize_status_str(NvmeSanitizeStatus status) {
    switch (status) {
        case NVME_SANITIZE_SUCCESS:         return "SUCCESS";
        case NVME_SANITIZE_NOT_SUPPORTED:   return "NOT SUPPORTED";
        case NVME_SANITIZE_FAILED:          return "FAILED";
        case NVME_SANITIZE_NOT_IMPLEMENTED: return "NOT IMPLEMENTED";
        default:                            return "UNKNOWN";
    }
}
