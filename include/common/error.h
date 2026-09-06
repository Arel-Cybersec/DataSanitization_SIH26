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

/* Return-if-error helper */
#define RETURN_IF_ERR(expr) \
    do { ErasecureError _e = (expr); if (_e != ERASECURE_OK) return _e; } while (0)

#endif /* ERASECURE_ERROR_H */
