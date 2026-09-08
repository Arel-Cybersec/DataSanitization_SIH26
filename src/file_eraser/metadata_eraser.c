#include "file_eraser/metadata_eraser.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#ifdef __linux__
#include <sys/xattr.h>
#endif

ErasecureError metadata_erase(const char *path, MetadataEraseResult *result) {
    if (!path || !result) return -1;
    memset(result, 0, sizeof(MetadataEraseResult));
    strncpy(result->limitation_note, "Filesystem journal, inode table, block allocation bitmaps are NOT controlled by userspace", sizeof(result->limitation_note) - 1);

    struct stat st;
    if (lstat(path, &st) != 0) return -1;

    struct timespec times[2] = {0};
    times[0].tv_sec = 0; times[0].tv_nsec = UTIME_NOW;
    times[1].tv_sec = 0; times[1].tv_nsec = UTIME_NOW;
    
    if (utimensat(AT_FDCWD, path, times, AT_SYMLINK_NOFOLLOW) == 0) {
        result->timestamps_cleared = true;
    }

#ifdef __linux__
    ssize_t list_size = llistxattr(path, NULL, 0);
    if (list_size > 0) {
        char *xattr_list = malloc(list_size);
        if (xattr_list) {
            list_size = llistxattr(path, xattr_list, list_size);
            char *key = xattr_list;
            while (key < xattr_list + list_size) {
                lremovexattr(path, key);
                key += strlen(key) + 1;
            }
            free(xattr_list);
            result->xattrs_cleared = true;
        }
    }
#endif

    return 0; // ERASECURE_SUCCESS
}
