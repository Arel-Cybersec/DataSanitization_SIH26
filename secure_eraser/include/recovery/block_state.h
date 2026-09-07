#ifndef ERASECURE_BLOCK_STATE_H
#define ERASECURE_BLOCK_STATE_H

#include "common/types.h"
#include "common/error.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

typedef enum {
    BLOCK_VALIDATION_UNKNOWN  = 0,
    BLOCK_VALIDATION_INVALID  = 1,
    BLOCK_VALIDATION_VALID    = 2,
} BlockValidation;

struct BlockState {
    uint64_t        block_number;
    uint32_t        confidence;     /* 0-100 */
    BlockValidation validation;
    char            file_type[32];  /* Detected file type name, e.g. "JPEG" */
    /* Generic opaque state blob for format-specific data */
    void           *format_data;
    size_t          format_data_len;
    /* Structural hints */
    uint64_t        offset_in_file; /* Byte offset hint within reconstructed file */
    uint32_t        crc32;          /* CRC/checksum if applicable */
    bool            crc_valid;
};

/**
 * @brief Initialize a BlockState for a specific block number.
 */
ErasecureError block_state_create(BlockState *bs, uint64_t block_number);

/**
 * @brief Free resources associated with a BlockState.
 */
void block_state_free(BlockState *bs);

/**
 * @brief Set opaque format-specific data for a block.
 */
ErasecureError block_state_set_format_data(BlockState *bs, const void *data, size_t len);

/**
 * @brief Retrieve format-specific data from a block state.
 */
ErasecureError block_state_get_format_data(const BlockState *bs, void *out_data, size_t *out_len);

/**
 * @brief Serialize BlockState to a buffer.
 */
ErasecureError block_state_serialize(const BlockState *bs, void *buf, size_t buf_len, size_t *written);

/**
 * @brief Deserialize BlockState from a buffer.
 */
ErasecureError block_state_deserialize(BlockState *bs, const void *buf, size_t buf_len);

#endif /* ERASECURE_BLOCK_STATE_H */
