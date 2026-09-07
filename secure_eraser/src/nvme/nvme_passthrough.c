#include "nvme/nvme_passthrough.h"
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#ifdef __linux__
#include <sys/ioctl.h>
#include <linux/nvme_ioctl.h>
#endif

void nvme_admin_cmd_init(NvmeAdminCommand *cmd) {
    if (cmd != NULL) {
        memset(cmd, 0, sizeof(*cmd));
    }
}

ErasecureError nvme_admin_execute(int fd, const NvmeAdminCommand *cmd, NvmeResult *result) {
    if (!cmd || !result) {
        return ERASECURE_ERR_INVALID_ARGUMENT;
    }
#ifdef __linux__
    struct nvme_admin_cmd acmd;
    memset(&acmd, 0, sizeof(acmd));
    acmd.opcode = cmd->opcode;
    acmd.nsid = cmd->nsid;
    acmd.cdw10 = cmd->cdw10;
    acmd.cdw11 = cmd->cdw11;
    acmd.cdw12 = cmd->cdw12;
    acmd.cdw13 = cmd->cdw13;
    acmd.cdw14 = cmd->cdw14;
    acmd.cdw15 = cmd->cdw15;
    acmd.addr = (__u64)(uintptr_t)cmd->data_buf;
    acmd.data_len = cmd->data_len;
    acmd.timeout_ms = cmd->timeout_ms;

    int ret = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &acmd);
    
    memset(result, 0, sizeof(*result));
    
    if (ret < 0) {
        if (errno == EACCES) {
            return ERASECURE_ERR_PERMISSION_DENIED;
        }
        return ERASECURE_ERR_IOCTL_FAILED;
    }

    result->status = ret;
    result->result = acmd.result;
    result->success = (ret == 0);
    result->sct = (ret >> 8) & 0x7;
    result->sc = ret & 0xFF;

    return ERASECURE_SUCCESS;
#else
    return ERASECURE_ERR_UNSUPPORTED_OS;
#endif
}

ErasecureError nvme_admin_execute_path(const char *device_path, const NvmeAdminCommand *cmd, NvmeResult *result) {
    if (!device_path || !cmd || !result) {
        return ERASECURE_ERR_INVALID_ARGUMENT;
    }
    
    int fd = open(device_path, O_RDONLY);
    if (fd < 0) {
        if (errno == EACCES) {
            return ERASECURE_ERR_PERMISSION_DENIED;
        }
        return ERASECURE_ERR_DEVICE_OPEN_FAILED;
    }
    
    ErasecureError err = nvme_admin_execute(fd, cmd, result);
    close(fd);
    return err;
}

const char *nvme_result_str(const NvmeResult *result, char *buf, size_t buf_len) {
    if (!result || !buf || buf_len == 0) return NULL;
    snprintf(buf, buf_len, "Status: 0x%x (SCT: 0x%x, SC: 0x%x), Result (CDW0): 0x%x, Success: %s",
             result->status, result->sct, result->sc, result->result,
             result->success ? "true" : "false");
    return buf;
}
