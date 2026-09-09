#ifndef ERASECURE_TEST_IMAGE_GEN_H
#define ERASECURE_TEST_IMAGE_GEN_H

#include <stdint.h>
#include <stddef.h>
#include "common/error.h"

void get_absolute_path(const char *prog_path, const char *target_filename, char *out_path, size_t max_len);
void ensure_sandbox_target(const char *filepath);

typedef enum {
    FRAG_PATTERN_CONTIGUOUS       = 0,  /* Files placed contiguously */
    FRAG_PATTERN_GAP              = 1,  /* Gaps of zero blocks between fragments */
    FRAG_PATTERN_OUT_OF_ORDER     = 2,  /* Fragments shuffled out of order */
    FRAG_PATTERN_INTERLEAVED      = 3,  /* Fragments of two files interleaved */
    FRAG_PATTERN_DUPLICATE_BLOCKS = 4,  /* Duplicate blocks inserted */
} FragPattern;

typedef struct {
    char        name[64];
    uint64_t    original_size;
    uint64_t    start_block;
    uint64_t   *actual_blocks;     /* Array of physical block numbers */
    size_t      block_count;
    char        sha256[65];
    FragPattern pattern_used;
} GroundTruthRecord;

typedef struct {
    char                image_path[256];
    uint64_t            image_size;
    uint64_t            block_size;
    uint64_t            total_blocks;
    uint8_t            *data;      /* In-memory buffer for the image */
    uint64_t            next_free_block;
    GroundTruthRecord  *records;
    size_t              record_count;
    size_t              record_capacity;
} SyntheticEvidenceImage;

/**
 * @brief Initialize a synthetic evidence image
 */
ErasecureError test_image_gen_init(SyntheticEvidenceImage *img, const char *path, uint64_t block_size, uint64_t total_blocks);

/**
 * @brief Destroy a synthetic evidence image
 */
void test_image_gen_destroy(SyntheticEvidenceImage *img);

/**
 * @brief Embed a file into the synthetic evidence image
 */
ErasecureError test_image_gen_embed_file(SyntheticEvidenceImage *img, const char *file_name, const void *data, size_t data_len, FragPattern pattern, GroundTruthRecord *record_out);

/**
 * @brief Write the synthetic evidence image to disk
 */
ErasecureError test_image_gen_write(const SyntheticEvidenceImage *img);

#endif /* ERASECURE_TEST_IMAGE_GEN_H */
