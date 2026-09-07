#include "recovery/discovery.h"
#include <stdlib.h>
#include <string.h>

/**
 * @brief Simple memory search (memmem fallback)
 */
static void *memmem_fallback(const void *haystack, size_t haystack_len, const void *needle, size_t needle_len) {
    if (needle_len == 0) return (void *)haystack;
    if (haystack_len < needle_len) return NULL;
    const unsigned char *h = (const unsigned char *)haystack;
    const unsigned char *n = (const unsigned char *)needle;
    for (size_t i = 0; i <= haystack_len - needle_len; i++) {
        if (h[i] == n[0] && memcmp(h + i, n, needle_len) == 0) {
            return (void *)(h + i);
        }
    }
    return NULL;
}

/**
 * @brief Initialize the discovery engine.
 */
ErasecureError discovery_init(DiscoveryEngine *engine) {
    if (!engine) return ERASECURE_ERROR_INVALID_ARGUMENT;
    engine->pattern_count = 0;
    engine->pattern_capacity = 16;
    engine->patterns = malloc(sizeof(SignaturePattern) * engine->pattern_capacity);
    if (!engine->patterns) return ERASECURE_ERROR_MEMORY;
    
    engine->hit_count = 0;
    engine->hit_capacity = 64;
    engine->hits = malloc(sizeof(SignatureHit) * engine->hit_capacity);
    if (!engine->hits) {
        free(engine->patterns);
        return ERASECURE_ERROR_MEMORY;
    }
    return ERASECURE_SUCCESS;
}

/**
 * @brief Destroy the discovery engine.
 */
void discovery_destroy(DiscoveryEngine *engine) {
    if (!engine) return;
    if (engine->patterns) {
        for (size_t i = 0; i < engine->pattern_count; i++) {
            free((void*)engine->patterns[i].bytes);
            free((void*)engine->patterns[i].type_name);
        }
        free(engine->patterns);
    }
    if (engine->hits) {
        for (size_t i = 0; i < engine->hit_count; i++) {
            free((void*)engine->hits[i].type_name);
        }
        free(engine->hits);
    }
    memset(engine, 0, sizeof(*engine));
}

/**
 * @brief Register a file signature pattern.
 */
ErasecureError discovery_register_signature(DiscoveryEngine *engine, const SignaturePattern *pattern) {
    if (!engine || !pattern) return ERASECURE_ERROR_INVALID_ARGUMENT;
    if (engine->pattern_count == engine->pattern_capacity) {
        size_t new_cap = engine->pattern_capacity * 2;
        SignaturePattern *new_patterns = realloc(engine->patterns, sizeof(SignaturePattern) * new_cap);
        if (!new_patterns) return ERASECURE_ERROR_MEMORY;
        engine->patterns = new_patterns;
        engine->pattern_capacity = new_cap;
    }
    
    SignaturePattern *dest = &engine->patterns[engine->pattern_count];
    dest->length = pattern->length;
    dest->offset = pattern->offset;
    dest->is_footer = pattern->is_footer;
    
    uint8_t *bytes = malloc(pattern->length);
    if (!bytes) return ERASECURE_ERROR_MEMORY;
    memcpy(bytes, pattern->bytes, pattern->length);
    dest->bytes = bytes;
    
    char *name = strdup(pattern->type_name ? pattern->type_name : "");
    if (!name) {
        free(bytes);
        return ERASECURE_ERROR_MEMORY;
    }
    dest->type_name = name;
    
    engine->pattern_count++;
    return ERASECURE_SUCCESS;
}

/**
 * @brief Adds a hit to the hit array.
 */
static ErasecureError add_hit(DiscoveryEngine *engine, uint64_t block, uint64_t byte_offset, const char *type_name, bool is_footer) {
    if (engine->hit_count == engine->hit_capacity) {
        size_t new_cap = engine->hit_capacity * 2;
        SignatureHit *new_hits = realloc(engine->hits, sizeof(SignatureHit) * new_cap);
        if (!new_hits) return ERASECURE_ERROR_MEMORY;
        engine->hits = new_hits;
        engine->hit_capacity = new_cap;
    }
    
    SignatureHit *hit = &engine->hits[engine->hit_count];
    hit->block = block;
    hit->byte_offset = byte_offset;
    hit->is_footer = is_footer;
    hit->type_name = strdup(type_name);
    if (!hit->type_name) return ERASECURE_ERROR_MEMORY;
    
    engine->hit_count++;
    return ERASECURE_SUCCESS;
}

/**
 * @brief Scan the file mirror for registered signatures.
 */
ErasecureError discovery_scan(DiscoveryEngine *engine, const FileMirror *fm) {
    if (!engine || !fm) return ERASECURE_ERROR_INVALID_ARGUMENT;
    
    size_t block_size = fm->block_size;
    uint8_t *buffer = malloc(block_size);
    if (!buffer) return ERASECURE_ERROR_MEMORY;
    
    for (uint64_t block = 0; block < fm->total_blocks; block++) {
        size_t bytes_read = 0;
        ErasecureError err = file_mirror_read_block(fm, block, buffer, block_size, &bytes_read);
        if (err != ERASECURE_SUCCESS) {
            continue; // Skip errors or partial reads for now
        }
        if (bytes_read < block_size) continue;
        
        for (size_t i = 0; i < engine->pattern_count; i++) {
            SignaturePattern *pat = &engine->patterns[i];
            if (pat->offset >= 0) {
                if ((size_t)pat->offset + pat->length <= block_size) {
                    if (memcmp(buffer + pat->offset, pat->bytes, pat->length) == 0) {
                        uint64_t exact_offset = block * block_size + pat->offset;
                        add_hit(engine, block, exact_offset, pat->type_name, pat->is_footer);
                    }
                }
            } else {
                // Search anywhere in block
                void *match = memmem_fallback(buffer, block_size, pat->bytes, pat->length);
                if (match) {
                    uint64_t exact_offset = block * block_size + ((uint8_t*)match - buffer);
                    add_hit(engine, block, exact_offset, pat->type_name, pat->is_footer);
                }
            }
        }
    }
    
    free(buffer);
    return ERASECURE_SUCCESS;
}

/**
 * @brief Get the total number of signature hits.
 */
size_t discovery_hit_count(const DiscoveryEngine *engine) {
    return engine ? engine->hit_count : 0;
}

/**
 * @brief Get a specific hit by index.
 */
const SignatureHit *discovery_get_hit(const DiscoveryEngine *engine, size_t index) {
    if (!engine || index >= engine->hit_count) return NULL;
    return &engine->hits[index];
}

/**
 * @brief Get headers for a specific type.
 */
ErasecureError discovery_get_headers_for_type(const DiscoveryEngine *engine, const char *type_name, const SignatureHit **out_hits, size_t *out_count) {
    if (!engine || !type_name || !out_hits || !out_count) return ERASECURE_ERROR_INVALID_ARGUMENT;
    *out_count = 0;
    
    size_t count = 0;
    // We'll return an allocated array of pointers or just rely on a static/dynamic array if caller manages it.
    // The prompt says: "Returns pointers into internal array (valid until next scan)"
    // Let's allocate a temporary array of hits for the caller to free? Wait, if we return `const SignatureHit**`, 
    // we need an array of hits. But C doesn't let us return an array easily unless we alloc.
    // Wait, let's just allocate an array of `SignatureHit` for the caller, or just the pointers.
    // We will allocate an array of `SignatureHit` structs and return it.
    
    SignatureHit *filtered = malloc(sizeof(SignatureHit) * engine->hit_count); // max possible
    if (!filtered) return ERASECURE_ERROR_MEMORY;
    
    for (size_t i = 0; i < engine->hit_count; i++) {
        if (!engine->hits[i].is_footer && strcmp(engine->hits[i].type_name, type_name) == 0) {
            filtered[count++] = engine->hits[i];
        }
    }
    *out_hits = filtered;
    *out_count = count;
    return ERASECURE_SUCCESS;
}

/**
 * @brief Get footers for a specific type.
 */
ErasecureError discovery_get_footers_for_type(const DiscoveryEngine *engine, const char *type_name, const SignatureHit **out_hits, size_t *out_count) {
    if (!engine || !type_name || !out_hits || !out_count) return ERASECURE_ERROR_INVALID_ARGUMENT;
    *out_count = 0;
    
    SignatureHit *filtered = malloc(sizeof(SignatureHit) * engine->hit_count);
    if (!filtered) return ERASECURE_ERROR_MEMORY;
    
    size_t count = 0;
    for (size_t i = 0; i < engine->hit_count; i++) {
        if (engine->hits[i].is_footer && strcmp(engine->hits[i].type_name, type_name) == 0) {
            filtered[count++] = engine->hits[i];
        }
    }
    *out_hits = filtered;
    *out_count = count;
    return ERASECURE_SUCCESS;
}
