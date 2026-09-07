#ifndef ERASECURE_NVME_PASSTHROUGH_H
#define ERASECURE_NVME_PASSTHROUGH_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "common/error.h"

typedef struct {
    uint8_t  opcode;      /* Admin command opcode */
    uint32_t nsid;        /* Namespace ID (0 for controller-level) */
    uint32_t cdw10;       /* Command Dword 10 */
    uint32_t cdw11;       /* Command Dword 11 */
    uint32_t cdw12;
    uint32_t cdw13;
    uint32_t cdw14;
    uint32_t cdw15;
    void    *data_buf;    /* Data buffer */
    uint32_t data_len;    /* Data buffer length */
    uint32_t timeout_ms;
} NvmeAdminCommand;

typedef struct {
    uint32_t status;      /* NVMe completion status */
    uint32_t result;      /* Command-specific result (CDW0) */
    bool     success;     /* true if status == 0 */
    uint8_t  sct;         /* Status Code Type */
    uint8_t  sc;          /* Status Code */
} NvmeResult;

/**
 * @brief Initializes an NVMe admin command structure.
 *
 * @param cmd Pointer to the command structure to initialize
 */
void nvme_admin_cmd_init(NvmeAdminCommand *cmd);

/**
 * @brief Executes an NVMe admin command using an open file descriptor.
 *
 * @param fd Open file descriptor to the NVMe device
 * @param cmd Pointer to the initialized command structure
 * @param result Pointer to structure to store command results
 * @return ErasecureError success or failure code
 */
ErasecureError nvme_admin_execute(int fd, const NvmeAdminCommand *cmd, NvmeResult *result);

/**
 * @brief Executes an NVMe admin command on a specified device path.
 *
 * @param device_path Path to the NVMe device
 * @param cmd Pointer to the initialized command structure
 * @param result Pointer to structure to store command results
 * @return ErasecureError success or failure code
 */
ErasecureError nvme_admin_execute_path(const char *device_path, const NvmeAdminCommand *cmd, NvmeResult *result);

/**
 * @brief Provides a string representation of the NVMe result.
 *
 * @param result Pointer to the NVMe result
 * @param buf Buffer to store the string representation
 * @param buf_len Length of the buffer
 * @return const char* Pointer to the buffer
 */
const char *nvme_result_str(const NvmeResult *result, char *buf, size_t buf_len);

#endif // ERASECURE_NVME_PASSTHROUGH_H
