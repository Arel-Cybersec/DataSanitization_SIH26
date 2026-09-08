#include "ata/ata_identify.h"
#include "ata/ata_passthrough.h"
#include <string.h>
#include <stdio.h>

#ifdef __linux__
#include <linux/fs.h>
#include <scsi/sg.h>
#include <sys/ioctl.h>

static void byteswap_string(char *dest, const uint16_t *src, size_t num_words) {
    size_t dest_idx = 0;
    for (size_t i = 0; i < num_words; i++) {
        dest[dest_idx++] = (char)(src[i] >> 8);
        dest[dest_idx++] = (char)(src[i] & 0xFF);
    }
    dest[dest_idx] = '\0';
    
    /* Strip trailing spaces */
    for (int i = (int)dest_idx - 1; i >= 0 && dest[i] == ' '; i--) {
        dest[i] = '\0';
    }
}

ErasecureError ata_identify_device(const char *device_path, AtaIdentifyData *data) {
    if (!device_path || !data) {
        return ERASECURE_ERR_INVALID_ARGUMENT;
    }

    uint8_t buffer[512] = {0};
    AtaCommand cmd;
    AtaResult result;

    ata_command_init(&cmd);
    cmd.command = 0xEC; /* IDENTIFY DEVICE */
    cmd.protocol = ATA_PROTO_PIO_IN;
    cmd.direction = -3; /* SG_DXFER_FROM_DEV */
    cmd.data_buf = buffer;
    cmd.data_len = sizeof(buffer);
    cmd.count = 1;

    ErasecureError err = ata_execute_path(device_path, &cmd, &result);
    if (err != ERASECURE_SUCCESS) {
        return err;
    }

    if (!result.success) {
        return ERASECURE_ERR_IOCTL_FAILED;
    }

    memset(data, 0, sizeof(AtaIdentifyData));
    
    /* Convert raw bytes to 16-bit words (little-endian assumed for SATA data buffer on host) */
    for (int i = 0; i < 256; i++) {
        data->raw_words[i] = (uint16_t)((buffer[i * 2 + 1] << 8) | buffer[i * 2]);
    }

    byteswap_string(data->serial, &data->raw_words[10], 10);
    byteswap_string(data->firmware, &data->raw_words[23], 4);
    byteswap_string(data->model, &data->raw_words[27], 20);

    /* Capacity */
    if (data->raw_words[83] & (1 << 10)) { /* 48-bit LBA supported */
        data->lba_capacity = ((uint64_t)data->raw_words[103] << 48) |
                             ((uint64_t)data->raw_words[102] << 32) |
                             ((uint64_t)data->raw_words[101] << 16) |
                             data->raw_words[100];
    }

    /* Sector size */
    data->logical_sector_size = 512;
    data->physical_sector_size = 512;
    if ((data->raw_words[106] & (1 << 12)) == (1 << 12)) {
        if (data->raw_words[106] & (1 << 14) && !(data->raw_words[106] & (1 << 15))) {
            uint32_t logical_size = (data->raw_words[118] << 16) | data->raw_words[117];
            data->logical_sector_size = logical_size * 2; /* words to bytes */
            data->physical_sector_size = data->logical_sector_size;
            
            if (data->raw_words[106] & (1 << 13)) { /* logical < physical */
                uint8_t exp = data->raw_words[106] & 0x0F;
                data->physical_sector_size = data->logical_sector_size * (1 << exp);
            }
        }
    }

    /* Security features */
    data->security_supported = (data->raw_words[82] & (1 << 1));
    data->security_enabled = (data->raw_words[85] & (1 << 1));
    data->security_locked = (data->raw_words[128] & (1 << 2));
    data->security_frozen = (data->raw_words[128] & (1 << 3));
    data->security_count_expired = (data->raw_words[128] & (1 << 4));
    data->enhanced_erase_supported = (data->raw_words[128] & (1 << 5));

    data->erase_time_normal = data->raw_words[89] & 0x7FFF;
    data->erase_time_enhanced = data->raw_words[90] & 0x7FFF;

    /* Sanitize features */
    if ((data->raw_words[59] & 0xC000) == 0x4000) {
        data->sanitize_supported = (data->raw_words[59] & (1 << 12));
        data->sanitize_crypto_scramble = (data->raw_words[59] & (1 << 13));
        data->sanitize_block_erase = (data->raw_words[59] & (1 << 14));
        data->sanitize_overwrite = (data->raw_words[59] & (1 << 15));
    }

    return ERASECURE_SUCCESS;
}

#else
/* Non-Linux implementations stubbed out */
ErasecureError ata_identify_device(const char *device_path, AtaIdentifyData *data) {
    (void)device_path; (void)data;
    return ERASECURE_ERR_NOT_SUPPORTED;
}
#endif

const char *ata_identify_summary(const AtaIdentifyData *data, char *buf, size_t buf_len) {
    if (!data || !buf || buf_len == 0) return "";
    snprintf(buf, buf_len,
             "Model: %s\nSerial: %s\nFirmware: %s\n"
             "LBA Capacity: %llu\n"
             "Security: Supported=%d, Enabled=%d, Locked=%d, Frozen=%d\n"
             "Sanitize: Crypto=%d, Block=%d, Overwrite=%d",
             data->model, data->serial, data->firmware,
             (unsigned long long)data->lba_capacity,
             data->security_supported, data->security_enabled,
             data->security_locked, data->security_frozen,
             data->sanitize_crypto_scramble, data->sanitize_block_erase,
             data->sanitize_overwrite);
    return buf;
}
