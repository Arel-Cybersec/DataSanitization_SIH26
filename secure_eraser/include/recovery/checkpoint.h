#ifndef ERASECURE_CHECKPOINT_H
#define ERASECURE_CHECKPOINT_H

#include <stdint.h>
#include "common/error.h"
#include "recovery/recovery_engine.h"

#define ERASECURE_CHECKPOINT_MAGIC 0x45435043
#define ERASECURE_CHECKPOINT_VERSION 1

typedef struct CheckpointHeader {
    uint32_t magic;
    uint32_t version;
    uint64_t timestamp;
    char evidence_hash[65];
    uint64_t block_size;
    uint64_t total_blocks;
    uint64_t covered_blocks;
    uint32_t candidate_count;
} CheckpointHeader;

/**
 * @brief Save a recovery checkpoint to a file.
 *
 * @param engine Pointer to RecoveryEngine.
 * @param checkpoint_path Path where the checkpoint will be saved.
 * @return ErasecureError Success or error code.
 */
ErasecureError checkpoint_save(const RecoveryEngine *engine, const char *checkpoint_path);

/**
 * @brief Load a recovery checkpoint from a file.
 *
 * @param engine Pointer to RecoveryEngine.
 * @param checkpoint_path Path to the checkpoint file to load.
 * @return ErasecureError Success or error code.
 */
ErasecureError checkpoint_load(RecoveryEngine *engine, const char *checkpoint_path);

#endif /* ERASECURE_CHECKPOINT_H */
