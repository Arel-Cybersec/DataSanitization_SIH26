#ifndef ERASECURE_FILE_VERIFY_H
#define ERASECURE_FILE_VERIFY_H

#include "common/error.h"
#include "sanitization/block_erase.h"
#include <stdint.h>
#include <stdbool.h>

typedef struct {
    bool           passed;
    uint64_t       bytes_checked;
    uint64_t       bytes_mismatched;
    ErasePattern   expected_pattern;
    char           note[256];
} FileVerifyResult;

/**
 * @brief Reads a file to verify that the expected pattern is written.
 */
ErasecureError file_verify_pattern(const char *path, ErasePattern pattern, FileVerifyResult *result);

#endif // ERASECURE_FILE_VERIFY_H
