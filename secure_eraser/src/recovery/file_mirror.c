#include "recovery/file_mirror.h"
#include "crypto/hash.h"
#include "common/constants.h"
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

ErasecureError file_mirror_open(FileMirror *fm, const char *image_path, uint64_t block_size) {
    if (!fm || !image_path || block_size == 0) return ERASECURE_ERR_INVALID_ARG;

    memset(fm, 0, sizeof(FileMirror));
    fm->fd = open(image_path, O_RDONLY);
    if (fm->fd < 0) return ERASECURE_ERR_FILE_NOT_FOUND;

    struct stat st;
    if (fstat(fm->fd, &st) < 0) {
        close(fm->fd);
        return ERASECURE_ERR_IO;
    }

    fm->image_size = (uint64_t)st.st_size;
    fm->block_size = block_size;
    fm->total_blocks = fm->image_size / block_size;
    fm->apparent_blocks = fm->total_blocks;
    strncpy(fm->image_path, image_path, sizeof(fm->image_path) - 1);

    fm->covered_mask = calloc(fm->total_blocks, sizeof(bool));
    if (!fm->covered_mask) {
        close(fm->fd);
        return ERASECURE_ERR_NO_MEM;
    }

    unsigned char digest[ERASECURE_SHA256_DIGEST_LEN];
    if (hash_sha256_file(image_path, digest) == 0) {
        hash_digest_to_hex(digest, fm->evidence_hash);
        fm->hash_verified = true;
    } else {
        fm->hash_verified = false;
    }

    return 0; // SUCCESS
}

ErasecureError file_mirror_read_block(const FileMirror *fm, uint64_t actual_block, void *buf) {
    if (!fm || !buf || actual_block >= fm->total_blocks) return ERASECURE_ERR_INVALID_ARG;

    ssize_t bytes_read = pread(fm->fd, buf, fm->block_size, (off_t)(actual_block * fm->block_size));
    if (bytes_read != (ssize_t)fm->block_size) {
        return ERASECURE_ERR_IO;
    }
    return 0; // SUCCESS
}

ErasecureError file_mirror_read_apparent_block(const FileMirror *fm, uint64_t apparent_block, void *buf, uint64_t *actual_block_out) {
    if (!fm || !buf || apparent_block >= fm->apparent_blocks) return ERASECURE_ERR_INVALID_ARG;

    uint64_t actual_block = file_mirror_apparent_to_actual(fm, apparent_block);
    if (actual_block == (uint64_t)-1) return ERASECURE_ERR_INVALID_ARG;

    if (actual_block_out) *actual_block_out = actual_block;
    return file_mirror_read_block(fm, actual_block, buf);
}

void file_mirror_mark_covered(FileMirror *fm, uint64_t actual_block) {
    if (fm && actual_block < fm->total_blocks) {
        if (!fm->covered_mask[actual_block]) {
            fm->covered_mask[actual_block] = true;
            if (fm->apparent_blocks > 0) fm->apparent_blocks--;
        }
    }
}

void file_mirror_unmark_covered(FileMirror *fm, uint64_t actual_block) {
    if (fm && actual_block < fm->total_blocks) {
        if (fm->covered_mask[actual_block]) {
            fm->covered_mask[actual_block] = false;
            fm->apparent_blocks++;
        }
    }
}

bool file_mirror_is_covered(const FileMirror *fm, uint64_t actual_block) {
    if (fm && actual_block < fm->total_blocks) {
        return fm->covered_mask[actual_block];
    }
    return false;
}

uint64_t file_mirror_apparent_to_actual(const FileMirror *fm, uint64_t apparent_block) {
    if (!fm || apparent_block >= fm->apparent_blocks) return (uint64_t)-1;
    
    uint64_t apparent_count = 0;
    for (uint64_t i = 0; i < fm->total_blocks; i++) {
        if (!fm->covered_mask[i]) {
            if (apparent_count == apparent_block) {
                return i;
            }
            apparent_count++;
        }
    }
    return (uint64_t)-1;
}

uint64_t file_mirror_actual_to_apparent(const FileMirror *fm, uint64_t actual_block) {
    if (!fm || actual_block >= fm->total_blocks) return (uint64_t)-1;
    
    uint64_t apparent_count = 0;
    for (uint64_t i = 0; i < actual_block; i++) {
        if (!fm->covered_mask[i]) {
            apparent_count++;
        }
    }
    return fm->covered_mask[actual_block] ? (uint64_t)-1 : apparent_count;
}

ErasecureError file_mirror_verify_integrity(const FileMirror *fm) {
    if (!fm || !fm->hash_verified) return ERASECURE_ERR_INVALID_ARG;
    
    unsigned char digest[ERASECURE_SHA256_DIGEST_LEN];
    char hex_hash[65];
    if (hash_sha256_file(fm->image_path, digest) != 0) {
        return ERASECURE_ERR_IO;
    }
    hash_digest_to_hex(digest, hex_hash);
    
    if (strcmp(fm->evidence_hash, hex_hash) != 0) {
        return ERASECURE_ERR_EVIDENCE_MODIFIED;
    }
    return 0; // SUCCESS
}

void file_mirror_close(FileMirror *fm) {
    if (fm) {
        if (fm->fd >= 0) close(fm->fd);
        if (fm->covered_mask) free(fm->covered_mask);
        memset(fm, 0, sizeof(FileMirror));
        fm->fd = -1;
    }
}
