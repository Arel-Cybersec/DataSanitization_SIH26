#ifndef ERASECURE_BLOCKMAP_H
#define ERASECURE_BLOCKMAP_H

#include "common/types.h"
#include "common/error.h"
#include "recovery/file_mirror.h"
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>

typedef struct {
    bool     covered;          /* Block content fully recovered */
    bool     is_duplicate;     /* Block is duplicate of another */
    bool     is_exemplar;      /* This block is the exemplar of its duplicate group */
    bool     is_zero;          /* Block contains all zeros */
    uint64_t exemplar_block;   /* Block number of exemplar if is_duplicate */
    uint32_t reservation_count;/* Number of candidates holding this block */
    char     hash[65];         /* SHA-256 hex hash of block content */
    bool     hash_computed;
} BlockmapEntry;

struct Blockmap {
    BlockmapEntry *primary;     /* Committed state */
    BlockmapEntry *shadow;      /* Accumulates updates from workers */
    uint64_t       block_count;
    pthread_mutex_t lock;       /* Protects shadow writes */
};

/**
 * @brief Create and initialize a blockmap.
 */
ErasecureError blockmap_create(Blockmap *bm, uint64_t block_count);

/**
 * @brief Destroy a blockmap and free its resources.
 */
void blockmap_destroy(Blockmap *bm);

/**
 * @brief Get read-only access to a block's primary state.
 */
const BlockmapEntry *blockmap_get(const Blockmap *bm, uint64_t block);

/**
 * @brief Update the covered status in the shadow map.
 */
ErasecureError blockmap_shadow_set_covered(Blockmap *bm, uint64_t block, bool covered);

/**
 * @brief Update the hash in the shadow map.
 */
ErasecureError blockmap_shadow_set_hash(Blockmap *bm, uint64_t block, const char *hash_hex);

/**
 * @brief Update the zero status in the shadow map.
 */
ErasecureError blockmap_shadow_set_zero(Blockmap *bm, uint64_t block, bool is_zero);

/**
 * @brief Mark a block as a duplicate in the shadow map.
 */
ErasecureError blockmap_shadow_set_duplicate(Blockmap *bm, uint64_t block, uint64_t exemplar);

/**
 * @brief Reserve a block (increment reservation count).
 */
ErasecureError blockmap_reserve(Blockmap *bm, uint64_t block);

/**
 * @brief Release a block (decrement reservation count).
 */
ErasecureError blockmap_release(Blockmap *bm, uint64_t block);

/**
 * @brief Get the current reservation count of a block.
 */
uint32_t blockmap_reservation_count(const Blockmap *bm, uint64_t block);

/**
 * @brief Merge the shadow map updates into the primary map.
 */
ErasecureError blockmap_merge_shadow(Blockmap *bm);

/**
 * @brief Compute hashes for all blocks in the evidence image.
 */
ErasecureError blockmap_compute_hashes(Blockmap *bm, const FileMirror *fm);

/**
 * @brief Identify duplicate blocks based on computed hashes.
 */
ErasecureError blockmap_find_duplicates(Blockmap *bm);

/**
 * @brief Count how many blocks are marked as covered.
 */
uint64_t blockmap_covered_count(const Blockmap *bm);

/**
 * @brief Count how many blocks are identified as all zeros.
 */
uint64_t blockmap_zero_count(const Blockmap *bm);

/**
 * @brief Count how many blocks are marked as duplicates.
 */
uint64_t blockmap_duplicate_count(const Blockmap *bm);

#endif /* ERASECURE_BLOCKMAP_H */
