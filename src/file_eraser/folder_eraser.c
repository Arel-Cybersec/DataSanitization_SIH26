#include "file_eraser/folder_eraser.h"
#include "common/constants.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>

#define MAX_SEEN_INODES 1024

typedef struct {
    dev_t dev;
    ino_t ino;
} InodeRecord;

static bool is_dangerous_path(const char *path) {
    if (strstr(path, "/dev/") == path || strstr(path, "/proc/") == path || strstr(path, "/sys/") == path) {
        return true;
    }
    return false;
}

static double get_elapsed_time(struct timespec start, struct timespec end) {
    return (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
}

void folder_erase_options_init(FolderEraseOptions *opts) {
    if (!opts) return;
    file_erase_options_init(&opts->file_opts);
    opts->remove_dirs = true;
    opts->follow_mount = false;
    opts->max_depth = 128; // fallback ERASECURE_MAX_ERASE_DEPTH
}

static ErasecureError folder_erase_recursive(const char *dir_path, const FolderEraseOptions *opts, FolderEraseResult *result, uint32_t depth, dev_t initial_dev, InodeRecord *seen, size_t *seen_count) {
    if (depth > opts->max_depth) {
        strncpy(result->error_message, "Max depth exceeded", sizeof(result->error_message) - 1);
        return -1;
    }

    struct stat st;
    if (lstat(dir_path, &st) != 0) return -1;
    
    if (!S_ISDIR(st.st_mode)) return -1;
    if (!opts->follow_mount && st.st_dev != initial_dev) return 0; // Skip cross-mount
    
    // Cycle detection
    for (size_t i = 0; i < *seen_count; i++) {
        if (seen[i].dev == st.st_dev && seen[i].ino == st.st_ino) {
            strncpy(result->error_message, "Cycle detected", sizeof(result->error_message) - 1);
            return ERASECURE_ERR_CYCLE_DETECTED;
        }
    }
    
    if (*seen_count < MAX_SEEN_INODES) {
        seen[*seen_count].dev = st.st_dev;
        seen[*seen_count].ino = st.st_ino;
        (*seen_count)++;
    }

    DIR *dir = opendir(dir_path);
    if (!dir) return -1;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        
        char path[1024];
        snprintf(path, sizeof(path), "%s/%s", dir_path, entry->d_name);
        
        struct stat est;
        if (lstat(path, &est) != 0) continue;
        
        if (S_ISLNK(est.st_mode)) {
            result->symlinks_skipped++;
            continue;
        } else if (S_ISREG(est.st_mode)) {
            FileEraseResult f_res;
            result->files_processed++;
            if (file_erase(path, &opts->file_opts, &f_res) == 0) {
                result->files_succeeded++;
                result->total_bytes_written += f_res.bytes_written;
            } else {
                result->files_failed++;
            }
        } else if (S_ISDIR(est.st_mode)) {
            folder_erase_recursive(path, opts, result, depth + 1, initial_dev, seen, seen_count);
        } else {
            // Devices, sockets, FIFOs - skip
        }
    }
    closedir(dir);
    
    if (opts->remove_dirs) {
        if (rmdir(dir_path) == 0) {
            result->dirs_removed++;
        }
    }
    
    return 0; // ERASECURE_SUCCESS
}

ErasecureError folder_erase(const char *dir_path, const FolderEraseOptions *opts, FolderEraseResult *result) {
    if (!dir_path || !opts || !result) return -1;
    memset(result, 0, sizeof(FolderEraseResult));
    strncpy(result->path, dir_path, sizeof(result->path) - 1);
    
    if (is_dangerous_path(dir_path)) {
        strncpy(result->error_message, "Dangerous path rejected", sizeof(result->error_message) - 1);
        result->result_code = ERASECURE_ERR_DANGEROUS_PATH;
        return result->result_code;
    }

    struct timespec start_time, end_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);

    struct stat st;
    if (lstat(dir_path, &st) != 0 || !S_ISDIR(st.st_mode)) {
        strncpy(result->error_message, "Not a directory", sizeof(result->error_message) - 1);
        result->result_code = -1;
        return result->result_code;
    }

    InodeRecord seen[MAX_SEEN_INODES];
    size_t seen_count = 0;
    
    result->result_code = folder_erase_recursive(dir_path, opts, result, 0, st.st_dev, seen, &seen_count);

    clock_gettime(CLOCK_MONOTONIC, &end_time);
    result->duration_seconds = get_elapsed_time(start_time, end_time);
    
    return result->result_code;
}
