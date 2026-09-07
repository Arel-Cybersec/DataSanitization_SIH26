/**
 * @file recovery_api.c
 * @brief Public Core API implementation.
 */
#define _POSIX_C_SOURCE 200809L

#include "recovery/recovery_api.h"
#include "recovery/recovery_engine.h"
#include "recovery/checkpoint.h"
#include "device/device_detect.h"
#include "device/device_info.h"
#include "sanitization/sanitizer.h"
#include "common/constants.h"
#include "common/error.h"

#include <stdlib.h>
#include <string.h>

struct RecoveryContext {
    RecoveryCaseOptions opts;
    RecoveryEngine      engine;
    bool                initialized;
};

/* ─── Sanitizer API Forwarders ───────────────────────────────── */

ErasecureError api_device_scan(StorageDevice *devices, size_t max_devices, size_t *found)
{
    return device_scan(devices, max_devices, found);
}

ErasecureError api_device_get_info(const char *path, StorageDevice *device)
{
    return device_get_info(path, device);
}

ErasecureError api_device_get_capabilities(const StorageDevice *device, DeviceCapabilities *caps)
{
    return device_get_capabilities(device, caps);
}

ErasecureError api_sanitizer_run(const StorageDevice *device,
                                 const SanitizationOptions *opts,
                                 SanitizationResult *result)
{
    return sanitizer_run(device, opts, result);
}

/* ─── Forensic Recovery API ──────────────────────────────────── */

ErasecureError recovery_create_case(const RecoveryCaseOptions *opts,
                                    RecoveryContext **ctx_out)
{
    if (!opts || !ctx_out) return ERASECURE_ERR_INVALID_ARG;
    *ctx_out = NULL;

    RecoveryContext *ctx = calloc(1, sizeof(RecoveryContext));
    if (!ctx) return ERASECURE_ERR_ALLOC;

    ctx->opts = *opts;
    uint64_t bs = opts->block_size ? opts->block_size : ERASECURE_DEFAULT_CARVE_BLOCK_SIZE;

    ErasecureError err = recovery_engine_init(&ctx->engine,
                                             opts->evidence_image_path,
                                             bs,
                                             opts->output_dir);
    if (err != ERASECURE_OK) {
        free(ctx);
        return err;
    }

    ctx->initialized = true;
    *ctx_out = ctx;
    return ERASECURE_OK;
}

ErasecureError recovery_start(RecoveryContext *ctx)
{
    if (!ctx || !ctx->initialized) return ERASECURE_ERR_INVALID_ARG;
    return recovery_engine_run(&ctx->engine);
}

ErasecureError recovery_pause(RecoveryContext *ctx)
{
    if (!ctx || !ctx->initialized) return ERASECURE_ERR_INVALID_ARG;
    recovery_engine_pause(&ctx->engine);
    return ERASECURE_OK;
}

ErasecureError recovery_resume(RecoveryContext *ctx)
{
    if (!ctx || !ctx->initialized) return ERASECURE_ERR_INVALID_ARG;
    recovery_engine_resume(&ctx->engine);
    return ERASECURE_OK;
}

ErasecureError recovery_cancel(RecoveryContext *ctx)
{
    if (!ctx || !ctx->initialized) return ERASECURE_ERR_INVALID_ARG;
    recovery_engine_cancel(&ctx->engine);
    return ERASECURE_OK;
}

ErasecureError recovery_checkpoint(RecoveryContext *ctx, const char *checkpoint_path)
{
    if (!ctx || !ctx->initialized || !checkpoint_path) return ERASECURE_ERR_INVALID_ARG;
    return checkpoint_save(&ctx->engine, checkpoint_path);
}

ErasecureError recovery_get_progress(const RecoveryContext *ctx,
                                     RecoveryProgress *progress)
{
    if (!ctx || !ctx->initialized || !progress) return ERASECURE_ERR_INVALID_ARG;

    memset(progress, 0, sizeof(*progress));
    const RecoveryEngine *eng = &ctx->engine;

    progress->total_blocks        = eng->mirror.total_blocks;
    progress->covered_blocks      = blockmap_covered_count(&eng->map);
    progress->processed_blocks    = progress->covered_blocks;
    progress->files_recovered     = eng->recovered_count;
    progress->candidates_in_queue = promising_queue_size(&eng->queue);
    progress->is_paused           = eng->paused;
    progress->is_cancelled        = eng->cancelled;
    progress->is_running          = !eng->paused && !eng->cancelled;

    if (progress->total_blocks > 0) {
        progress->percentage = ((double)progress->covered_blocks / (double)progress->total_blocks) * 100.0;
    }

    snprintf(progress->current_phase, sizeof(progress->current_phase),
             "%s", progress->is_cancelled ? "CANCELLED" :
                   progress->is_paused    ? "PAUSED" : "RUNNING");

    return ERASECURE_OK;
}

void recovery_close_case(RecoveryContext *ctx)
{
    if (!ctx) return;
    if (ctx->initialized) {
        recovery_engine_destroy(&ctx->engine);
    }
    free(ctx);
}
