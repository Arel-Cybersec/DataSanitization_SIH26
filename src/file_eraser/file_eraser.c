#include "file_eraser/file_eraser.h"
#include "file_eraser/file_verify.h"
#include "crypto/hash.h"
#include "common/constants.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>
#include <openssl/rand.h>
#include <libgen.h>

#define CHUNK_SIZE 4096

void file_erase_options_init(FileEraseOptions *opts) {
    if (!opts) return;
    opts->pattern = ERASE_PATTERN_RANDOM;
    opts->passes = 3;
    opts->verify_after = true;
    opts->remove_file = true;
    opts->sync_parent = true;
}

static bool is_dangerous_path(const char *path) {
    // In a full implementation, iterate over ERASECURE_DANGEROUS_PATHS
    if (strstr(path, "/dev/") == path || strstr(path, "/proc/") == path || strstr(path, "/sys/") == path) {
        return true;
    }
    return false;
}

static double get_elapsed_time(struct timespec start, struct timespec end) {
    return (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
}

ErasecureError file_erase(const char *path, const FileEraseOptions *opts, FileEraseResult *result) {
    if (!path || !opts || !result) return -1;
    
    memset(result, 0, sizeof(FileEraseResult));
    strncpy(result->path, path, sizeof(result->path) - 1);
    result->scope = FILE_ERASE_SCOPE_LOGICAL;
    strncpy(result->scope_note, "Logical overwrite; NAND not guaranteed", sizeof(result->scope_note) - 1);
    
    struct timespec start_time, end_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);

    if (is_dangerous_path(path)) {
        strncpy(result->error_message, "Dangerous path rejected", sizeof(result->error_message) - 1);
        result->result_code = ERASECURE_ERR_DANGEROUS_PATH;
        return result->result_code;
    }

    struct stat st;
    if (lstat(path, &st) != 0) {
        strncpy(result->error_message, "lstat failed", sizeof(result->error_message) - 1);
        result->result_code = -1;
        return result->result_code;
    }

    if (!S_ISREG(st.st_mode)) {
        strncpy(result->error_message, "Not a regular file (symlink or special)", sizeof(result->error_message) - 1);
        result->result_code = ERASECURE_ERR_SYMLINK_ATTACK;
        return result->result_code;
    }
    
    result->original_size = st.st_size;

    // Compute pre-hash (assume hash_sha256_file exists in hash.h)
    // hash_sha256_file(path, result->pre_hash_sha256);

    int fd = open(path, O_WRONLY | O_NOFOLLOW);
    if (fd < 0) {
        strncpy(result->error_message, "Failed to open file", sizeof(result->error_message) - 1);
        result->result_code = -1;
        return result->result_code;
    }

    byte_t *buffer = malloc(CHUNK_SIZE);
    if (!buffer) {
        close(fd);
        result->result_code = -1;
        return result->result_code;
    }

    for (uint32_t pass = 0; pass < opts->passes; pass++) {
        lseek(fd, 0, SEEK_SET);
        uint64_t bytes_left = result->original_size;
        
        if (opts->pattern == ERASE_PATTERN_ZERO) {
            memset(buffer, 0x00, CHUNK_SIZE);
        } else if (opts->pattern == ERASE_PATTERN_ONE) {
            memset(buffer, 0xFF, CHUNK_SIZE);
        }

        while (bytes_left > 0) {
            size_t to_write = (bytes_left < CHUNK_SIZE) ? bytes_left : CHUNK_SIZE;
            
            if (opts->pattern == ERASE_PATTERN_RANDOM) {
                RAND_bytes(buffer, to_write);
            }

            ssize_t written = write(fd, buffer, to_write);
            if (written < 0) {
                free(buffer);
                close(fd);
                strncpy(result->error_message, "Write failed", sizeof(result->error_message) - 1);
                result->result_code = -1;
                return result->result_code;
            }
            bytes_left -= written;
            result->bytes_written += written;
        }
        fsync(fd);
        result->passes_completed++;
    }

    OPENSSL_cleanse(buffer, CHUNK_SIZE);
    free(buffer);
    close(fd);

    if (opts->verify_after) {
        FileVerifyResult v_res;
        file_verify_pattern(path, opts->pattern, &v_res);
        result->verified = true;
        result->verification_passed = v_res.passed;
    }

    if (opts->remove_file) {
        if (unlink(path) == 0) {
            result->file_removed = true;
            if (opts->sync_parent) {
                char path_copy[256];
                strncpy(path_copy, path, sizeof(path_copy) - 1);
                char *dir = dirname(path_copy);
                int dir_fd = open(dir, O_RDONLY | O_DIRECTORY);
                if (dir_fd >= 0) {
                    fsync(dir_fd);
                    close(dir_fd);
                }
            }
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &end_time);
    result->duration_seconds = get_elapsed_time(start_time, end_time);
    result->result_code = 0; // ERASECURE_SUCCESS
    return result->result_code;
}

ErasecureError file_erase_batch(const char **paths, size_t count, const FileEraseOptions *opts, FileEraseResult *results) {
    if (!paths || !opts || !results) return -1;
    for (size_t i = 0; i < count; i++) {
        file_erase(paths[i], opts, &results[i]);
    }
    return 0; // ERASECURE_SUCCESS
}
