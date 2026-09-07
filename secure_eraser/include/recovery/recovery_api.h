/**
 * @file recovery_api.h
 * @brief Public Core API for future GTK 3 GUI and CLI frontends.
 *
 * Exposes clean, high-level handles and contracts for:
 *   - Device discovery and capability query
 *   - Drive sanitization execution and progress polling
 *   - Forensic recovery case management, execution, pause, resume, and cancellation
 *   - Audit query and report generation
 *
 * This API is strictly GUI-independent. No GTK or UI dependencies.
 */
#ifndef ERASECURE_RECOVERY_API_H
#define ERASECURE_RECOVERY_API_H

#include "common/types.h"
#include "common/error.h"
#include "device/device.h"
#include "sanitization/sanitizer.h"
#include <stdint.h>
#include <stdbool.h>

/* ─── Opaque Recovery Context Handle ─────────────────────────── */
typedef struct RecoveryContext RecoveryContext;

/* ─── High-Level Recovery Progress (GUI-pollable) ────────────── */
struct RecoveryProgress {
    uint64_t total_blocks;
    uint64_t processed_blocks;
    uint64_t covered_blocks;
    uint64_t files_recovered;
    uint64_t candidates_in_queue;
    double   percentage;          /* 0.0 - 100.0 */
    bool     is_running;
    bool     is_paused;
    bool     is_cancelled;
    char     current_phase[32];   /* "PHASE C", "PHASE F1", "PHASE F2", "IDLE" */
};

/* ─── Case Creation Options ──────────────────────────────────── */
typedef struct {
    char     case_id[64];
    char     investigator[64];
    char     evidence_image_path[256];
    char     output_dir[256];
    uint64_t block_size;          /* 0 for default 512 */
    uint32_t worker_threads;      /* 0 for default 4 */
} RecoveryCaseOptions;

/* ─── Sanitizer API (convenience forwarders) ─────────────────── */
ErasecureError api_device_scan(StorageDevice *devices, size_t max_devices, size_t *found);
ErasecureError api_device_get_info(const char *path, StorageDevice *device);
ErasecureError api_device_get_capabilities(const StorageDevice *device, DeviceCapabilities *caps);

ErasecureError api_sanitizer_run(const StorageDevice *device,
                                 const SanitizationOptions *opts,
                                 SanitizationResult *result);

/* ─── Forensic Recovery API ──────────────────────────────────── */
ErasecureError recovery_create_case(const RecoveryCaseOptions *opts,
                                    RecoveryContext **ctx_out);

ErasecureError recovery_start(RecoveryContext *ctx);
ErasecureError recovery_pause(RecoveryContext *ctx);
ErasecureError recovery_resume(RecoveryContext *ctx);
ErasecureError recovery_cancel(RecoveryContext *ctx);
ErasecureError recovery_checkpoint(RecoveryContext *ctx, const char *checkpoint_path);

ErasecureError recovery_get_progress(const RecoveryContext *ctx,
                                     RecoveryProgress *progress);

void recovery_close_case(RecoveryContext *ctx);

#endif /* ERASECURE_RECOVERY_API_H */
