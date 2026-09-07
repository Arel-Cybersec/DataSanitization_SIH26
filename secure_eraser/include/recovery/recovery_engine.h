#ifndef ERASECURE_RECOVERY_ENGINE_H
#define ERASECURE_RECOVERY_ENGINE_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include "common/error.h"
#include "common/types.h"
#include "recovery/reassembly.h"

typedef struct RecoveryEngine {
    FileMirror mirror;
    Blockmap map;
    DiscoveryEngine discovery;
    FileTypeRegistry registry;
    PromisingQueue queue;
    ReassemblyOptions reassembly_opts;
    char output_dir[256];
    bool paused;
    bool cancelled;
    uint64_t recovered_count;
    uint64_t validated_count;
    uint64_t promising_count;
    pthread_mutex_t state_lock;
} RecoveryEngine;

/**
 * @brief Initialize the recovery engine.
 *
 * @param engine Pointer to RecoveryEngine.
 * @param evidence_image Path to evidence image.
 * @param block_size Block size in bytes.
 * @param output_dir Path to output directory.
 * @return ErasecureError Success or error code.
 */
ErasecureError recovery_engine_init(RecoveryEngine *engine, const char *evidence_image, uint64_t block_size, const char *output_dir);

/**
 * @brief Destroy the recovery engine and free resources.
 *
 * @param engine Pointer to RecoveryEngine.
 */
void recovery_engine_destroy(RecoveryEngine *engine);

/**
 * @brief Run contiguous recovery phase (C).
 *
 * @param engine Pointer to RecoveryEngine.
 * @return ErasecureError Success or error code.
 */
ErasecureError recovery_engine_phase_c(RecoveryEngine *engine);

/**
 * @brief Run promising fragment reassembly phase (F1).
 *
 * @param engine Pointer to RecoveryEngine.
 * @return ErasecureError Success or error code.
 */
ErasecureError recovery_engine_phase_f1(RecoveryEngine *engine);

/**
 * @brief Run speculative phase (F2).
 *
 * @param engine Pointer to RecoveryEngine.
 * @return ErasecureError Success or error code.
 */
ErasecureError recovery_engine_phase_f2(RecoveryEngine *engine);

/**
 * @brief Run all recovery phases iteratively.
 *
 * @param engine Pointer to RecoveryEngine.
 * @return ErasecureError Success or error code.
 */
ErasecureError recovery_engine_run(RecoveryEngine *engine);

/**
 * @brief Pause the recovery engine.
 *
 * @param engine Pointer to RecoveryEngine.
 */
void recovery_engine_pause(RecoveryEngine *engine);

/**
 * @brief Resume the recovery engine.
 *
 * @param engine Pointer to RecoveryEngine.
 */
void recovery_engine_resume(RecoveryEngine *engine);

/**
 * @brief Cancel the recovery engine.
 *
 * @param engine Pointer to RecoveryEngine.
 */
void recovery_engine_cancel(RecoveryEngine *engine);

#endif /* ERASECURE_RECOVERY_ENGINE_H */
