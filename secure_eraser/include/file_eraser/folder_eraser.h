#ifndef ERASECURE_FOLDER_ERASER_H
#define ERASECURE_FOLDER_ERASER_H

#include "file_eraser/file_eraser.h"
#include "common/error.h"
#include <stdbool.h>
#include <stdint.h>

typedef struct FolderEraseOptions {
    FileEraseOptions   file_opts;     /* Options for each file */
    bool               remove_dirs;   /* rmdir() empty dirs after processing */
    bool               follow_mount;  /* false = stop at mount boundaries */
    uint32_t           max_depth;     /* Max recursion depth */
} FolderEraseOptions;

typedef struct FolderEraseResult {
    ErasecureError     result_code;
    char               path[256];
    uint64_t           files_processed;
    uint64_t           files_succeeded;
    uint64_t           files_failed;
    uint64_t           dirs_removed;
    uint64_t           symlinks_skipped;
    uint64_t           total_bytes_written;
    double             duration_seconds;
    char               error_message[256];
} FolderEraseResult;

/**
 * @brief Initializes FolderEraseOptions with default secure values.
 */
void folder_erase_options_init(FolderEraseOptions *opts);

/**
 * @brief Recursively and securely erases files in a directory.
 */
ErasecureError folder_erase(const char *dir_path, const FolderEraseOptions *opts, FolderEraseResult *result);

#endif // ERASECURE_FOLDER_ERASER_H
