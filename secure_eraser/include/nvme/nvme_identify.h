#ifndef ERASECURE_NVME_IDENTIFY_H
#define ERASECURE_NVME_IDENTIFY_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "common/error.h"

/* NVMe Controller Identify data (CNS=01h) — selected fields */
typedef struct {
    char     model[41];        /* bytes 24-63, ASCII */
    char     serial[21];       /* bytes 4-23, ASCII */
    char     firmware[9];      /* bytes 64-71, ASCII */
    uint16_t vid;              /* Vendor ID */
    uint16_t ssvid;            /* Subsystem Vendor ID */
    uint32_t nn;               /* Number of Namespaces */
    uint8_t  sanicap;          /* Sanitize Capabilities (byte 328) */
    bool     sanitize_crypto;  /* Crypto Erase supported */
    bool     sanitize_block;   /* Block Erase supported */
    bool     sanitize_overwrite; /* Overwrite supported */
    bool     format_supported; /* Format NVM supported (OACS bit 1) */
    uint16_t oacs;             /* Optional Admin Command Support */
    uint8_t  fna;              /* Format NVM Attributes */
} NvmeControllerData;

/* NVMe Namespace Identify data (CNS=00h) — selected fields */
typedef struct {
    uint64_t nsze;             /* Namespace Size (in LBAs) */
    uint64_t ncap;             /* Namespace Capacity */
    uint64_t nuse;             /* Namespace Utilization */
    uint32_t lba_size;         /* Current LBA data size in bytes */
    uint8_t  flbas;            /* Formatted LBA Size index */
    uint8_t  nlbaf;            /* Number of LBA Formats */
} NvmeNamespaceData;

/**
 * @brief Identifies an NVMe controller and retrieves its data.
 *
 * @param device_path Path to the NVMe device
 * @param ctrl Pointer to a structure to store controller data
 * @return ErasecureError success or failure code
 */
ErasecureError nvme_identify_controller(const char *device_path, NvmeControllerData *ctrl);

/**
 * @brief Identifies an NVMe namespace and retrieves its data.
 *
 * @param device_path Path to the NVMe device
 * @param nsid Namespace ID to identify
 * @param ns Pointer to a structure to store namespace data
 * @return ErasecureError success or failure code
 */
ErasecureError nvme_identify_namespace(const char *device_path, uint32_t nsid, NvmeNamespaceData *ns);

/**
 * @brief Generates a string summary of the NVMe controller data.
 *
 * @param ctrl Pointer to the controller data
 * @param buf Buffer to store the summary
 * @param buf_len Length of the buffer
 * @return const char* Pointer to the buffer
 */
const char *nvme_controller_summary(const NvmeControllerData *ctrl, char *buf, size_t buf_len);

#endif // ERASECURE_NVME_IDENTIFY_H
