/**
 * @file error.c
 * @brief Error string table and logging helpers.
 */
#include "common/error.h"

#include <stdio.h>
#include <string.h>

/* ─── Error string table ─────────────────────────────────────── */
typedef struct {
    ErasecureError code;
    const char    *message;
} ErrorEntry;

static const ErrorEntry error_table[] = {
    { ERASECURE_OK,                    "Success" },
    { ERASECURE_ERR_GENERIC,           "Generic error" },
    { ERASECURE_ERR_INVALID_ARG,       "Invalid argument" },
    { ERASECURE_ERR_NULL_PTR,          "Null pointer" },
    { ERASECURE_ERR_NOT_IMPLEMENTED,   "Not implemented" },
    { ERASECURE_ERR_UNSUPPORTED,       "Unsupported operation" },
    { ERASECURE_ERR_OVERFLOW,          "Integer overflow" },
    { ERASECURE_ERR_IO,                "I/O error" },
    { ERASECURE_ERR_OPEN_FAILED,       "Failed to open file/device" },
    { ERASECURE_ERR_READ_FAILED,       "Read failed" },
    { ERASECURE_ERR_WRITE_FAILED,      "Write failed" },
    { ERASECURE_ERR_SEEK_FAILED,       "Seek failed" },
    { ERASECURE_ERR_SYNC_FAILED,       "Fsync failed" },
    { ERASECURE_ERR_STAT_FAILED,       "Stat failed" },
    { ERASECURE_ERR_ALLOC,             "Memory allocation failed" },
    { ERASECURE_ERR_DEVICE_NOT_FOUND,  "Device not found" },
    { ERASECURE_ERR_DEVICE_READ_ONLY,  "Device is read-only" },
    { ERASECURE_ERR_DEVICE_SCAN_FAIL,  "Device scan failed" },
    { ERASECURE_ERR_NOT_A_DEVICE,      "Path is not a storage device" },
    { ERASECURE_ERR_REAL_DEVICE_PATH,  "Real device path rejected in test mode" },
    { ERASECURE_ERR_SAFETY_BLOCKED,    "Operation blocked for safety" },
    { ERASECURE_ERR_CRYPTO,            "Cryptographic error" },
    { ERASECURE_ERR_HASH_FAILED,       "Hash computation failed" },
    { ERASECURE_ERR_KEY_UNAVAILABLE,   "Encryption key unavailable" },
    { ERASECURE_ERR_VERIFY_FAILED,     "Verification failed" },
    { ERASECURE_ERR_PATTERN_MISMATCH,  "Pattern mismatch during verification" },
    { ERASECURE_ERR_AUDIT,             "Audit error" },
    { ERASECURE_ERR_DB_OPEN,           "Database open failed" },
    { ERASECURE_ERR_DB_EXEC,           "Database execution failed" },
    { ERASECURE_ERR_CHAIN_TAMPERED,    "Audit chain tamper detected" },
};

#define ERROR_TABLE_SIZE ((int)(sizeof(error_table) / sizeof(error_table[0])))

const char *erasecure_strerror(ErasecureError err)
{
    for (int i = 0; i < ERROR_TABLE_SIZE; ++i) {
        if (error_table[i].code == err) {
            return error_table[i].message;
        }
    }
    return "Unknown error code";
}

void erasecure_log_error(const char *file, int line, const char *func,
                         ErasecureError err, const char *msg)
{
    fprintf(stderr, "[ERASECURE ERROR] %s:%d %s(): %s (code %d) -- %s\n",
            file, line, func, erasecure_strerror(err), (int)err,
            msg ? msg : "");
}
