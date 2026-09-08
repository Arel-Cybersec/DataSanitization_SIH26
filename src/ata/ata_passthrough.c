#include "ata/ata_passthrough.h"
#include <string.h>
#include <stdio.h>

#ifdef __linux__
#include <linux/fs.h>
#include <scsi/sg.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#define ATA_16_OPCODE 0x85
#define SENSE_BUF_LEN 32

void ata_command_init(AtaCommand *cmd) {
    if (cmd) {
        memset(cmd, 0, sizeof(AtaCommand));
        cmd->timeout_ms = 5000; /* Default 5 second timeout */
        cmd->direction = -1; /* SG_DXFER_NONE value equivalent */
    }
}

ErasecureError ata_execute(int fd, const AtaCommand *cmd, AtaResult *result) {
    if (fd < 0 || !cmd || !result) {
        return ERASECURE_ERR_INVALID_ARGUMENT;
    }

    memset(result, 0, sizeof(AtaResult));

    uint8_t cdb[16] = {0};
    uint8_t sense[SENSE_BUF_LEN] = {0};
    sg_io_hdr_t io_hdr;

    cdb[0] = ATA_16_OPCODE;
    cdb[1] = (cmd->protocol << 1); 
    
    cdb[2] = 0x20; 
    if (cmd->direction == -3 /* SG_DXFER_FROM_DEV */) {
        cdb[2] |= 0x08;
    }
    if (cmd->data_buf && cmd->data_len > 0) {
        cdb[2] |= 0x02; 
    }

    cdb[3] = cmd->feature_ext;
    cdb[4] = cmd->feature;
    cdb[5] = cmd->count_ext;
    cdb[6] = cmd->count;
    cdb[7] = cmd->lba_low_ext;
    cdb[8] = cmd->lba_low;
    cdb[9] = cmd->lba_mid_ext;
    cdb[10] = cmd->lba_mid;
    cdb[11] = cmd->lba_high_ext;
    cdb[12] = cmd->lba_high;
    cdb[13] = cmd->device;
    cdb[14] = cmd->command;
    cdb[15] = 0; /* Control */

    memset(&io_hdr, 0, sizeof(sg_io_hdr_t));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = sizeof(cdb);
    io_hdr.mx_sb_len = sizeof(sense);
    io_hdr.dxfer_direction = cmd->direction;
    io_hdr.dxfer_len = (unsigned int)cmd->data_len;
    io_hdr.dxferp = cmd->data_buf;
    io_hdr.cmdp = cdb;
    io_hdr.sbp = sense;
    io_hdr.timeout = cmd->timeout_ms;

    if (ioctl(fd, SG_IO, &io_hdr) < 0) {
        if (errno == EACCES) return ERASECURE_ERR_PERMISSION_DENIED;
        return ERASECURE_ERR_IOCTL_FAILED;
    }

    result->sg_status = io_hdr.status;
    result->success = true;

    /* Parse sense data if present and in descriptor format (0x72 or 0x73) */
    if (io_hdr.sb_len_wr > 0 && (sense[0] == 0x72 || sense[0] == 0x73)) {
        result->sense_key = sense[1] & 0x0F;
        result->asc = sense[2];
        result->ascq = sense[3];
        
        /* Search for ATA Return Descriptor (0x09) */
        int offset = 8;
        while (offset < io_hdr.sb_len_wr - 1) {
            uint8_t desc_type = sense[offset];
            uint8_t desc_len = sense[offset + 1];
            if (desc_type == 0x09 && desc_len >= 12 && offset + 13 < SENSE_BUF_LEN) {
                result->error = sense[offset + 3];
                result->count = sense[offset + 5];
                result->lba_low = sense[offset + 7];
                result->lba_mid = sense[offset + 9];
                result->lba_high = sense[offset + 11];
                result->device = sense[offset + 12];
                result->status = sense[offset + 13];

                if (result->status & 0x01) { /* ERR bit set */
                    result->success = false;
                }
                break;
            }
            offset += desc_len + 2;
        }
    }

    if (io_hdr.status != 0 && result->success) {
        result->success = false; /* SCSI level error */
    }

    return ERASECURE_SUCCESS;
}

ErasecureError ata_execute_path(const char *device_path, const AtaCommand *cmd, AtaResult *result) {
    if (!device_path || !cmd || !result) {
        return ERASECURE_ERR_INVALID_ARGUMENT;
    }

    int fd = open(device_path, O_RDONLY | O_NONBLOCK);
    if (fd < 0) {
        if (errno == EACCES) return ERASECURE_ERR_PERMISSION_DENIED;
        return ERASECURE_ERR_IOCTL_FAILED;
    }

    ErasecureError err = ata_execute(fd, cmd, result);
    close(fd);
    return err;
}

#else
/* Non-Linux implementations stubbed out */
void ata_command_init(AtaCommand *cmd) { (void)cmd; }
ErasecureError ata_execute(int fd, const AtaCommand *cmd, AtaResult *result) {
    (void)fd; (void)cmd; (void)result;
    return ERASECURE_ERR_NOT_SUPPORTED;
}
ErasecureError ata_execute_path(const char *device_path, const AtaCommand *cmd, AtaResult *result) {
    (void)device_path; (void)cmd; (void)result;
    return ERASECURE_ERR_NOT_SUPPORTED;
}
#endif

const char *ata_result_str(const AtaResult *result, char *buf, size_t buf_len) {
    if (!result || !buf || buf_len == 0) return "";
    snprintf(buf, buf_len, 
             "Success: %s, Status: 0x%02X, Error: 0x%02X, SG Status: 0x%02X", 
             result->success ? "true" : "false", 
             result->status, result->error, result->sg_status);
    return buf;
}
