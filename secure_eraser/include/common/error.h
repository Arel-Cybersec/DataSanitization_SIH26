/**
 * @file error.h
 * @brief Error codes and error-handling helpers for EraseCure.
 */
#ifndef ERASECURE_ERROR_H
#define ERASECURE_ERROR_H

/* ─── Master error enumeration ───────────────────────────────── */
typedef enum {
    ERASECURE_OK                    =  0,

    /* General errors */
    ERASECURE_ERR_GENERIC           = -1,
    ERASECURE_ERR_INVALID_ARG       = -2,
    ERASECURE_ERR_NULL_PTR          = -3,
    ERASECURE_ERR_NOT_IMPLEMENTED   = -4,
    ERASECURE_ERR_UNSUPPORTED       = -5,
    ERASECURE_ERR_OVERFLOW          = -6,

    /* I/O errors */
    ERASECURE_ERR_IO                = -10,
    ERASECURE_ERR_OPEN_FAILED       = -11,
    ERASECURE_ERR_READ_FAILED       = -12,
    ERASECURE_ERR_WRITE_FAILED      = -13,
    ERASECURE_ERR_SEEK_FAILED       = -14,
    ERASECURE_ERR_SYNC_FAILED       = -15,
    ERASECURE_ERR_STAT_FAILED       = -16,

    /* Memory errors */
    ERASECURE_ERR_ALLOC             = -20,

    /* Device errors */
    ERASECURE_ERR_DEVICE_NOT_FOUND  = -30,
    ERASECURE_ERR_DEVICE_READ_ONLY  = -31,
    ERASECURE_ERR_DEVICE_SCAN_FAIL  = -32,
    ERASECURE_ERR_NOT_A_DEVICE      = -33,

    /* Safety / security errors */
    ERASECURE_ERR_REAL_DEVICE_PATH  = -40,  /* test mode: physical path rejected */
    ERASECURE_ERR_SAFETY_BLOCKED    = -41,

    /* Crypto errors */
    ERASECURE_ERR_CRYPTO            = -50,
    ERASECURE_ERR_HASH_FAILED       = -51,
    ERASECURE_ERR_KEY_UNAVAILABLE   = -52,

    /* Verification errors */
    ERASECURE_ERR_VERIFY_FAILED     = -60,
    ERASECURE_ERR_PATTERN_MISMATCH  = -61,

    /* Audit / DB errors */
    ERASECURE_ERR_AUDIT             = -70,
    ERASECURE_ERR_DB_OPEN           = -71,
    ERASECURE_ERR_DB_EXEC           = -72,
    ERASECURE_ERR_CHAIN_TAMPERED    = -73,

    /* Physical device errors (Phases 2–6) */
    ERASECURE_ERR_PERMISSION_DENIED = -80,
    ERASECURE_ERR_DEVICE_BUSY       = -81,
    ERASECURE_ERR_DEVICE_MOUNTED    = -82,
    ERASECURE_ERR_TIMEOUT           = -83,
    ERASECURE_ERR_CANCELLED         = -84,
    ERASECURE_ERR_IDENTITY_CHANGED  = -85,  /* device identity mismatch */
    ERASECURE_ERR_CONFIRMATION      = -86,  /* destructive op not confirmed */
    ERASECURE_ERR_IOCTL_FAILED      = -87,

    /* File/folder eraser errors (Phase 8) */
    ERASECURE_ERR_PATH_TRAVERSAL    = -90,
    ERASECURE_ERR_SYMLINK_ATTACK    = -91,
    ERASECURE_ERR_DANGEROUS_PATH    = -92,
    ERASECURE_ERR_DIR_NOT_EMPTY     = -93,
    ERASECURE_ERR_CYCLE_DETECTED    = -94,

    /* Recovery / forensic errors (Phases 9–27) */
    ERASECURE_ERR_EVIDENCE_MISMATCH = -100,
    ERASECURE_ERR_EVIDENCE_MODIFIED = -101,
    ERASECURE_ERR_CHECKPOINT_INVALID = -102,
    ERASECURE_ERR_CHECKPOINT_VERSION = -103,
    ERASECURE_ERR_VALIDATION_FAILED = -104,
    ERASECURE_ERR_QUEUE_FULL        = -105,
    ERASECURE_ERR_QUEUE_EMPTY       = -106,
    ERASECURE_ERR_NOT_FOUND         = -107,
    ERASECURE_ERR_ALREADY_EXISTS    = -108,
} ErasecureError;

/**
 * @brief Return a human-readable string for an ErasecureError code.
 * @param err  The error code.
 * @return     Static string; never NULL.
 */
const char *erasecure_strerror(ErasecureError err);

/**
 * @brief Log an error message to stderr with file/line context.
 * @note  Prefer the ERASECURE_LOG_ERR() macro.
 */
void erasecure_log_error(const char *file, int line, const char *func,
                         ErasecureError err, const char *msg);

/* Convenience macro */
#define ERASECURE_LOG_ERR(err, msg) \
    erasecure_log_error(__FILE__, __LINE__, __func__, (err), (msg))

/* Compatibility aliases across modules */
#define ERASECURE_SUCCESS               ERASECURE_OK
#define ERASECURE_ERROR_INVALID_PARAM   ERASECURE_ERR_INVALID_ARG
#define ERASECURE_ERROR_INVALID_ARGUMENT ERASECURE_ERR_INVALID_ARG
#define ERASECURE_ERROR_MEMORY          ERASECURE_ERR_ALLOC
#define ERASECURE_ERROR_NOT_FOUND       ERASECURE_ERR_NOT_FOUND
#define ERASECURE_ERROR_INVALID_STATE   ERASECURE_ERR_INVALID_ARG
#define ERASECURE_ERROR_IO              ERASECURE_ERR_IO
#define ERASECURE_ERR_INVALID_ARGUMENT  ERASECURE_ERR_INVALID_ARG
#define ERASECURE_ERR_NOT_SUPPORTED     ERASECURE_ERR_UNSUPPORTED
#define ERASECURE_ERR_DEVICE_OPEN_FAILED ERASECURE_ERR_OPEN_FAILED
#define ERASECURE_ERR_UNSUPPORTED_OS    ERASECURE_ERR_UNSUPPORTED

#endif /* ERASECURE_ERROR_H */
