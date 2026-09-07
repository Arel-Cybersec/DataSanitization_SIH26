#ifndef ERASECURE_RECOVERY_OUTPUT_H
#define ERASECURE_RECOVERY_OUTPUT_H

#include <stdint.h>
#include <stddef.h>
#include "common/error.h"

typedef struct RecoveredFileMetadata {
    char uuid[37];
    char file_type[32];
    uint64_t size_bytes;
    char sha256[65];
    uint32_t confidence;
    uint64_t start_block;
    uint64_t block_count;
    char output_path[512];
} RecoveredFileMetadata;

/**
 * @brief Initialize recovery output directories.
 *
 * @param base_dir Base output directory.
 * @return ErasecureError Success or error code.
 */
ErasecureError recovery_output_init(const char *base_dir);

/**
 * @brief Write recovered file data to the corresponding output directory.
 *
 * @param base_dir Base output directory.
 * @param category Category (VALIDATED, PROMISING, INPROGRESS).
 * @param ext File extension.
 * @param data Data buffer to write.
 * @param len Length of the data buffer.
 * @param meta Pointer to RecoveredFileMetadata.
 * @param path_out Output buffer to store the written file path.
 * @param path_out_len Length of the path_out buffer.
 * @return ErasecureError Success or error code.
 */
ErasecureError recovery_output_write_file(const char *base_dir, const char *category, const char *ext, const void *data, size_t len, const RecoveredFileMetadata *meta, char *path_out, size_t path_out_len);

/**
 * @brief Write metadata to manifest.jsonl.
 *
 * @param base_dir Base output directory.
 * @param meta Pointer to RecoveredFileMetadata.
 * @return ErasecureError Success or error code.
 */
ErasecureError recovery_output_write_manifest(const char *base_dir, const RecoveredFileMetadata *meta);

#endif /* ERASECURE_RECOVERY_OUTPUT_H */
