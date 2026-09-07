#include "recovery/blockmap.h"
#include "crypto/hash.h"
#include <stdlib.h>
#include <string.h>

ErasecureError blockmap_create(Blockmap *bm, uint64_t block_count) {
    if (!bm || block_count == 0) return ERASECURE_ERR_INVALID_ARG;

    bm->block_count = block_count;
    bm->primary = calloc(block_count, sizeof(BlockmapEntry));
    bm->shadow = calloc(block_count, sizeof(BlockmapEntry));

    if (!bm->primary || !bm->shadow) {
        if (bm->primary) free(bm->primary);
        if (bm->shadow) free(bm->shadow);
        return ERASECURE_ERR_NO_MEM;
    }

    pthread_mutex_init(&bm->lock, NULL);
    return 0;
}

void blockmap_destroy(Blockmap *bm) {
    if (bm) {
        pthread_mutex_destroy(&bm->lock);
        if (bm->primary) free(bm->primary);
        if (bm->shadow) free(bm->shadow);
        memset(bm, 0, sizeof(Blockmap));
    }
}

const BlockmapEntry *blockmap_get(const Blockmap *bm, uint64_t block) {
    if (!bm || block >= bm->block_count) return NULL;
    return &bm->primary[block];
}

ErasecureError blockmap_shadow_set_covered(Blockmap *bm, uint64_t block, bool covered) {
    if (!bm || block >= bm->block_count) return ERASECURE_ERR_INVALID_ARG;
    pthread_mutex_lock(&bm->lock);
    bm->shadow[block].covered = covered;
    pthread_mutex_unlock(&bm->lock);
    return 0;
}

ErasecureError blockmap_shadow_set_hash(Blockmap *bm, uint64_t block, const char *hash_hex) {
    if (!bm || block >= bm->block_count || !hash_hex) return ERASECURE_ERR_INVALID_ARG;
    pthread_mutex_lock(&bm->lock);
    strncpy(bm->shadow[block].hash, hash_hex, 64);
    bm->shadow[block].hash[64] = '\0';
    bm->shadow[block].hash_computed = true;
    pthread_mutex_unlock(&bm->lock);
    return 0;
}

ErasecureError blockmap_shadow_set_zero(Blockmap *bm, uint64_t block, bool is_zero) {
    if (!bm || block >= bm->block_count) return ERASECURE_ERR_INVALID_ARG;
    pthread_mutex_lock(&bm->lock);
    bm->shadow[block].is_zero = is_zero;
    pthread_mutex_unlock(&bm->lock);
    return 0;
}

ErasecureError blockmap_shadow_set_duplicate(Blockmap *bm, uint64_t block, uint64_t exemplar) {
    if (!bm || block >= bm->block_count || exemplar >= bm->block_count) return ERASECURE_ERR_INVALID_ARG;
    pthread_mutex_lock(&bm->lock);
    bm->shadow[block].is_duplicate = true;
    bm->shadow[block].exemplar_block = exemplar;
    pthread_mutex_unlock(&bm->lock);
    return 0;
}

ErasecureError blockmap_reserve(Blockmap *bm, uint64_t block) {
    if (!bm || block >= bm->block_count) return ERASECURE_ERR_INVALID_ARG;
    pthread_mutex_lock(&bm->lock);
    bm->shadow[block].reservation_count++;
    pthread_mutex_unlock(&bm->lock);
    return 0;
}

ErasecureError blockmap_release(Blockmap *bm, uint64_t block) {
    if (!bm || block >= bm->block_count) return ERASECURE_ERR_INVALID_ARG;
    pthread_mutex_lock(&bm->lock);
    if (bm->shadow[block].reservation_count > 0) {
        bm->shadow[block].reservation_count--;
    }
    pthread_mutex_unlock(&bm->lock);
    return 0;
}

uint32_t blockmap_reservation_count(const Blockmap *bm, uint64_t block) {
    if (!bm || block >= bm->block_count) return 0;
    return bm->shadow[block].reservation_count; // Read from shadow or primary depending on context, shadow is safer for latest count
}

ErasecureError blockmap_merge_shadow(Blockmap *bm) {
    if (!bm) return ERASECURE_ERR_INVALID_ARG;
    pthread_mutex_lock(&bm->lock);
    memcpy(bm->primary, bm->shadow, bm->block_count * sizeof(BlockmapEntry));
    pthread_mutex_unlock(&bm->lock);
    return 0;
}

ErasecureError blockmap_compute_hashes(Blockmap *bm, const FileMirror *fm) {
    if (!bm || !fm) return ERASECURE_ERR_INVALID_ARG;
    
    void *buf = malloc(fm->block_size);
    if (!buf) return ERASECURE_ERR_NO_MEM;

    unsigned char digest[32]; // ERASECURE_SHA256_DIGEST_LEN
    char hex_hash[65];
    
    for (uint64_t i = 0; i < bm->block_count; i++) {
        if (file_mirror_read_block(fm, i, buf) == 0) {
            hash_sha256_buffer(buf, fm->block_size, digest);
            hash_digest_to_hex(digest, hex_hash);
            
            // Check for zero block
            bool is_zero = true;
            for (size_t j = 0; j < fm->block_size; j++) {
                if (((uint8_t*)buf)[j] != 0) {
                    is_zero = false;
                    break;
                }
            }
            
            blockmap_shadow_set_hash(bm, i, hex_hash);
            blockmap_shadow_set_zero(bm, i, is_zero);
        }
    }
    
    free(buf);
    return blockmap_merge_shadow(bm);
}

// A simple structure for sorting and finding duplicates
typedef struct {
    uint64_t block;
    char hash[65];
} HashEntry;

static int compare_hashes(const void *a, const void *b) {
    const HashEntry *ha = (const HashEntry *)a;
    const HashEntry *hb = (const HashEntry *)b;
    return strcmp(ha->hash, hb->hash);
}

ErasecureError blockmap_find_duplicates(Blockmap *bm) {
    if (!bm) return ERASECURE_ERR_INVALID_ARG;
    
    HashEntry *entries = malloc(bm->block_count * sizeof(HashEntry));
    if (!entries) return ERASECURE_ERR_NO_MEM;
    
    uint64_t valid_count = 0;
    for (uint64_t i = 0; i < bm->block_count; i++) {
        if (bm->primary[i].hash_computed && !bm->primary[i].is_zero) {
            entries[valid_count].block = i;
            strncpy(entries[valid_count].hash, bm->primary[i].hash, 65);
            valid_count++;
        }
    }
    
    qsort(entries, valid_count, sizeof(HashEntry), compare_hashes);
    
    for (uint64_t i = 1; i < valid_count; i++) {
        if (strcmp(entries[i].hash, entries[i-1].hash) == 0) {
            uint64_t exemplar = entries[i-1].block;
            uint64_t duplicate = entries[i].block;
            
            pthread_mutex_lock(&bm->lock);
            bm->shadow[exemplar].is_exemplar = true;
            bm->shadow[duplicate].is_duplicate = true;
            bm->shadow[duplicate].exemplar_block = exemplar;
            pthread_mutex_unlock(&bm->lock);
        }
    }
    
    free(entries);
    return blockmap_merge_shadow(bm);
}

uint64_t blockmap_covered_count(const Blockmap *bm) {
    if (!bm) return 0;
    uint64_t count = 0;
    for (uint64_t i = 0; i < bm->block_count; i++) {
        if (bm->primary[i].covered) count++;
    }
    return count;
}

uint64_t blockmap_zero_count(const Blockmap *bm) {
    if (!bm) return 0;
    uint64_t count = 0;
    for (uint64_t i = 0; i < bm->block_count; i++) {
        if (bm->primary[i].is_zero) count++;
    }
    return count;
}

uint64_t blockmap_duplicate_count(const Blockmap *bm) {
    if (!bm) return 0;
    uint64_t count = 0;
    for (uint64_t i = 0; i < bm->block_count; i++) {
        if (bm->primary[i].is_duplicate) count++;
    }
    return count;
}
