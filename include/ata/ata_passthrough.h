#ifndef ERASECURE_ATA_PASSTHROUGH_H
#define ERASECURE_ATA_PASSTHROUGH_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "common/error.h"
#include "common/types.h"

/* Protocol constants */
#define ATA_PROTO_NON_DATA    3
#define ATA_PROTO_PIO_IN      4
#define ATA_PROTO_PIO_OUT     5
#define ATA_PROTO_DMA         6

/**
 * @brief Represents an ATA-16 command to be sent to a device.
 */
typedef struct {
    uint8_t  command;       /* ATA command register */
    uint8_t  feature;       /* Feature register */
    uint8_t  feature_ext;   /* Feature ext (48-bit) */
    uint8_t  count;         /* Sector count */
    uint8_t  count_ext;
    uint8_t  lba_low;
    uint8_t  lba_mid;
    uint8_t  lba_high;
    uint8_t  lba_low_ext;
    uint8_t  lba_mid_ext;
    uint8_t  lba_high_ext;
    uint8_t  device;        /* Device/head register */
    uint8_t  protocol;      /* ATA protocol (PIO/DMA/non-data) */
    int      direction;     /* SG_DXFER_NONE / TO_DEV / FROM_DEV */
    void    *data_buf;      /* Data buffer (or NULL for non-data) */
    size_t   data_len;
    uint32_t timeout_ms;    /* Timeout in milliseconds */
} AtaCommand;

/**
 * @brief Represents the result of an ATA-16 command execution.
 */
typedef struct {
    uint8_t  status;        /* ATA status register */
    uint8_t  error;         /* ATA error register */
    uint8_t  count;         /* Sector count (completion) */
    uint8_t  lba_low;
    uint8_t  lba_mid;
    uint8_t  lba_high;
    uint8_t  device;
    uint8_t  sense_key;
    uint8_t  asc;
    uint8_t  ascq;
    bool     success;       /* true if no error */
    int      sg_status;     /* raw SG_IO status */
} AtaResult;

/**
 * @brief Initializes an ATA command structure with default values.
 * @param cmd Pointer to the AtaCommand structure to initialize.
 */
void ata_command_init(AtaCommand *cmd);

/**
 * @brief Executes an ATA command on a block device using a file descriptor.
 * @param fd Open file descriptor to the block device.
 * @param cmd The ATA command to execute.
 * @param result The result structure to populate.
 * @return ERASECURE_SUCCESS on success, or an appropriate error code.
 */
ErasecureError ata_execute(int fd, const AtaCommand *cmd, AtaResult *result);

/**
 * @brief Executes an ATA command on a block device using its path.
 * @param device_path Path to the block device.
 * @param cmd The ATA command to execute.
 * @param result The result structure to populate.
 * @return ERASECURE_SUCCESS on success, or an appropriate error code.
 */
ErasecureError ata_execute_path(const char *device_path, const AtaCommand *cmd, AtaResult *result);

/**
 * @brief Generates a string representation of an ATA result.
 * @param result The ATA result to format.
 * @param buf Buffer to write the string into.
 * @param buf_len Size of the buffer.
 * @return Pointer to the buffer.
 */
const char *ata_result_str(const AtaResult *result, char *buf, size_t buf_len);

#endif /* ERASECURE_ATA_PASSTHROUGH_H */
