#ifndef ERASECURE_FILE_ERASER_H
#define ERASECURE_FILE_ERASER_H

#include "common/types.h"
#include "common/error.h"
#include "sanitization/block_erase.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

typedef enum {
    FILE_ERASE_SCOPE_LOGICAL,     /* Logical overwrite only */
    FILE_ERASE_SCOPE_DEVICE,      /* Device-level sanitization (not applicable here) */
} FileEraseScope;

typedef struct FileEraseOptions {
    ErasePattern       pattern;       /* zero/one/random */
    uint32_t           passes;        /* Number of overwrite passes */
    bool               verify_after;  /* Verify pattern after overwrite */
    bool               remove_file;   /* unlink() after overwrite */
    bool               sync_parent;   /* fsync parent directory after unlink */
} FileEraseOptions;

typedef struct FileEraseResult {
    ErasecureError     result_code;
    FileEraseScope     scope;           /* Always LOGICAL for regular files */
    char               path[256];
    uint64_t           original_size;
    uint64_t           bytes_written;
    uint32_t           passes_completed;
    bool               file_removed;
    bool               verified;
    bool               verification_passed;
    char               pre_hash_sha256[65];   /* SHA-256 before erase */
    char               post_hash_sha256[65];  /* SHA-256 after erase (pattern check) */
    double             duration_seconds;
    char               error_message[256];
    char               scope_note[256];       /* e.g. 'Logical overwrite; NAND not guaranteed' */
} FileEraseResult;

/**
 * @brief Initializes FileEraseOptions with default secure values.
 */
void file_erase_options_init(FileEraseOptions *opts);

/**
 * @brief Securely erases a single file with the given options.
 */
ErasecureError file_erase(const char *path, const FileEraseOptions *opts, FileEraseResult *result);

/**
 * @brief Erases a batch of files using the same options.
 */
ErasecureError file_erase_batch(const char **paths, size_t count, const FileEraseOptions *opts, FileEraseResult *results);

#endif // ERASECURE_FILE_ERASER_H
