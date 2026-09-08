#ifndef ERASECURE_METADATA_ERASER_H
#define ERASECURE_METADATA_ERASER_H

#include "common/error.h"
#include <stdbool.h>

typedef struct {
    bool  timestamps_cleared;   /* atime/mtime/ctime reset attempted */
    bool  name_removed;         /* Directory entry removed */
    bool  xattrs_cleared;       /* Extended attributes removed */
    char  limitation_note[256]; /* What cannot be guaranteed */
} MetadataEraseResult;

/**
 * @brief Resets timestamps and extended attributes on a file.
 */
ErasecureError metadata_erase(const char *path, MetadataEraseResult *result);

#endif // ERASECURE_METADATA_ERASER_H
