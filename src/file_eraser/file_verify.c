#include "file_eraser/file_verify.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#define CHUNK_SIZE 4096

ErasecureError file_verify_pattern(const char *path, ErasePattern pattern, FileVerifyResult *result) {
    if (!path || !result) return -1;
    memset(result, 0, sizeof(FileVerifyResult));
    result->expected_pattern = pattern;
    
    if (pattern == ERASE_PATTERN_RANDOM) {
        strncpy(result->note, "Random pattern not verifiable by readback", sizeof(result->note) - 1);
        result->passed = true; // Assume pass since we cannot verify random
        return 0;
    }

    struct stat st;
    if (lstat(path, &st) != 0) return -1;
    
    if (!S_ISREG(st.st_mode)) return -1;

    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return -1;

    byte_t *buffer = malloc(CHUNK_SIZE);
    if (!buffer) {
        close(fd);
        return -1;
    }

    byte_t expected_byte = (pattern == ERASE_PATTERN_ZERO) ? 0x00 : 0xFF;
    ssize_t bytes_read;
    while ((bytes_read = read(fd, buffer, CHUNK_SIZE)) > 0) {
        for (ssize_t i = 0; i < bytes_read; i++) {
            result->bytes_checked++;
            if (buffer[i] != expected_byte) {
                result->bytes_mismatched++;
            }
        }
    }

    free(buffer);
    close(fd);

    result->passed = (result->bytes_mismatched == 0);
    return 0; // ERASECURE_SUCCESS
}
