#ifndef ERASECURE_FILE_MIRROR_H
#define ERASECURE_FILE_MIRROR_H

#include "common/types.h"
#include "common/error.h"
#include <stdint.h>
#include <stdbool.h>

struct FileMirror {
    int         fd;                    /* Read-only file descriptor */
    uint64_t    image_size;            /* Total evidence image size in bytes */
    uint64_t    block_size;            /* Block size for carving */
    uint64_t    total_blocks;          /* image_size / block_size */
    char        image_path[256];
    char        evidence_hash[65];     /* SHA-256 of entire evidence image */
    bool        hash_verified;         /* true after initial hash computed */
    /* Apparent image: blocks marked covered are hidden */
    bool       *covered_mask;          /* One bit per block: true = covered */
    uint64_t    apparent_blocks;       /* total_blocks - covered count */
};

/**
 * @brief Open a read-only evidence image and initialize the file mirror.
 */
ErasecureError file_mirror_open(FileMirror *fm, const char *image_path, uint64_t block_size);

/**
 * @brief Read a block from the actual (physical) evidence image.
 */
ErasecureError file_mirror_read_block(const FileMirror *fm, uint64_t actual_block, void *buf);

/**
 * @brief Read a block from the apparent (uncovered) evidence image.
 */
ErasecureError file_mirror_read_apparent_block(const FileMirror *fm, uint64_t apparent_block, void *buf, uint64_t *actual_block_out);

/**
 * @brief Mark a block as covered (removed from apparent image).
 */
void file_mirror_mark_covered(FileMirror *fm, uint64_t actual_block);

/**
 * @brief Unmark a block as covered (restored to apparent image).
 */
void file_mirror_unmark_covered(FileMirror *fm, uint64_t actual_block);

/**
 * @brief Check if a block is marked as covered.
 */
bool file_mirror_is_covered(const FileMirror *fm, uint64_t actual_block);

/**
 * @brief Convert an apparent block index to an actual block index.
 */
uint64_t file_mirror_apparent_to_actual(const FileMirror *fm, uint64_t apparent_block);

/**
 * @brief Convert an actual block index to an apparent block index.
 */
uint64_t file_mirror_actual_to_apparent(const FileMirror *fm, uint64_t actual_block);

/**
 * @brief Verify the integrity of the evidence image by hashing it.
 */
ErasecureError file_mirror_verify_integrity(const FileMirror *fm);

/**
 * @brief Close the file mirror and free resources.
 */
void file_mirror_close(FileMirror *fm);

#endif /* ERASECURE_FILE_MIRROR_H */
