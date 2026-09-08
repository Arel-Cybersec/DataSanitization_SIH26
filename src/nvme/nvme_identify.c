#include "nvme/nvme_identify.h"
#include "nvme/nvme_passthrough.h"
#include <string.h>
#include <stdio.h>

#define NVME_OPCODE_IDENTIFY 0x06

static void trim_ascii(char *dest, const uint8_t *src, size_t len, size_t dest_size) {
    size_t copy_len = len < (dest_size - 1) ? len : (dest_size - 1);
    memcpy(dest, src, copy_len);
    dest[copy_len] = '\0';
    for (int i = (int)copy_len - 1; i >= 0; i--) {
        if (dest[i] == ' ') dest[i] = '\0';
        else break;
    }
}

ErasecureError nvme_identify_controller(const char *device_path, NvmeControllerData *ctrl) {
    if (!device_path || !ctrl) return ERASECURE_ERR_INVALID_ARGUMENT;

    uint8_t buf[4096];
    memset(buf, 0, sizeof(buf));

    NvmeAdminCommand cmd;
    nvme_admin_cmd_init(&cmd);
    cmd.opcode = NVME_OPCODE_IDENTIFY;
    cmd.cdw10 = 0x01; // CNS = 01h (Identify Controller)
    cmd.data_buf = buf;
    cmd.data_len = sizeof(buf);

    NvmeResult result;
    ErasecureError err = nvme_admin_execute_path(device_path, &cmd, &result);
    if (err != ERASECURE_SUCCESS) {
        memset(buf, 0, sizeof(buf)); // Zero sensitive buffer on error
        return err;
    }
    if (!result.success) {
        memset(buf, 0, sizeof(buf)); // Zero sensitive buffer on error
        return ERASECURE_ERR_IOCTL_FAILED;
    }

    memset(ctrl, 0, sizeof(*ctrl));
    ctrl->vid = (uint16_t)buf[0] | ((uint16_t)buf[1] << 8);
    ctrl->ssvid = (uint16_t)buf[2] | ((uint16_t)buf[3] << 8);
    
    trim_ascii(ctrl->serial, &buf[4], 20, sizeof(ctrl->serial));
    trim_ascii(ctrl->model, &buf[24], 40, sizeof(ctrl->model));
    trim_ascii(ctrl->firmware, &buf[64], 8, sizeof(ctrl->firmware));
    
    ctrl->oacs = (uint16_t)buf[256] | ((uint16_t)buf[257] << 8);
    ctrl->fna = buf[527];
    
    ctrl->sanicap = buf[328];
    ctrl->sanitize_crypto = (ctrl->sanicap & (1 << 2)) != 0;
    ctrl->sanitize_block = (ctrl->sanicap & (1 << 1)) != 0;
    ctrl->sanitize_overwrite = (ctrl->sanicap & (1 << 0)) != 0;
    
    ctrl->format_supported = (ctrl->oacs & (1 << 1)) != 0;
    
    ctrl->nn = (uint32_t)buf[516] | ((uint32_t)buf[517] << 8) | ((uint32_t)buf[518] << 16) | ((uint32_t)buf[519] << 24);

    memset(buf, 0, sizeof(buf)); // Zero sensitive buffer after use

    return ERASECURE_SUCCESS;
}

ErasecureError nvme_identify_namespace(const char *device_path, uint32_t nsid, NvmeNamespaceData *ns) {
    if (!device_path || !ns) return ERASECURE_ERR_INVALID_ARGUMENT;

    uint8_t buf[4096];
    memset(buf, 0, sizeof(buf));

    NvmeAdminCommand cmd;
    nvme_admin_cmd_init(&cmd);
    cmd.opcode = NVME_OPCODE_IDENTIFY;
    cmd.nsid = nsid;
    cmd.cdw10 = 0x00; // CNS = 00h (Identify Namespace)
    cmd.data_buf = buf;
    cmd.data_len = sizeof(buf);

    NvmeResult result;
    ErasecureError err = nvme_admin_execute_path(device_path, &cmd, &result);
    if (err != ERASECURE_SUCCESS) {
        memset(buf, 0, sizeof(buf));
        return err;
    }
    if (!result.success) {
        memset(buf, 0, sizeof(buf));
        return ERASECURE_ERR_IOCTL_FAILED;
    }

    memset(ns, 0, sizeof(*ns));
    
    memcpy(&ns->nsze, &buf[0], sizeof(uint64_t));
    memcpy(&ns->ncap, &buf[8], sizeof(uint64_t));
    memcpy(&ns->nuse, &buf[16], sizeof(uint64_t));

    ns->nlbaf = buf[25];
    ns->flbas = buf[26];
    
    uint8_t lbaf_idx = ns->flbas & 0x0F;
    if (lbaf_idx <= ns->nlbaf) {
        uint8_t ds = buf[128 + lbaf_idx * 4 + 2];
        if (ds >= 9) ns->lba_size = 1 << ds;
        else ns->lba_size = 512;
    } else {
        ns->lba_size = 512;
    }

    memset(buf, 0, sizeof(buf));
    return ERASECURE_SUCCESS;
}

const char *nvme_controller_summary(const NvmeControllerData *ctrl, char *buf, size_t buf_len) {
    if (!ctrl || !buf || buf_len == 0) return NULL;
    snprintf(buf, buf_len, "Model: %s, Serial: %s, FW: %s, Sanitize (Cry: %d, Blk: %d, Ow: %d)",
             ctrl->model, ctrl->serial, ctrl->firmware,
             ctrl->sanitize_crypto, ctrl->sanitize_block, ctrl->sanitize_overwrite);
    return buf;
}
