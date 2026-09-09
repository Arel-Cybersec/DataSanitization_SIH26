#include "testing/test_image_gen.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <sys/stat.h>
#include <libgen.h>
#include <unistd.h>

#define DEFAULT_TEST_IMG "zero_test.img"

ErasecureError test_image_gen_init(SyntheticEvidenceImage *img, const char *path, uint64_t block_size, uint64_t total_blocks) {
    if (!img || !path || block_size == 0 || total_blocks == 0) return ERR_INVALID_PARAM;

    memset(img, 0, sizeof(SyntheticEvidenceImage));
    strncpy(img->image_path, path, sizeof(img->image_path) - 1);
    img->block_size = block_size;
    img->total_blocks = total_blocks;
    img->image_size = block_size * total_blocks;
    img->next_free_block = 0;

    img->data = calloc(total_blocks, block_size);
    if (!img->data) return ERR_MEMORY_ALLOCATION_FAILED;

    img->record_capacity = 16;
    img->records = calloc(img->record_capacity, sizeof(GroundTruthRecord));
    if (!img->records) {
        free(img->data);
        return ERR_MEMORY_ALLOCATION_FAILED;
    }

    return ERR_SUCCESS;
}

void get_absolute_path(const char *prog_path, const char *target_filename, char *out_path, size_t max_len) {
    char temp_path[1024];
    snprintf(temp_path, sizeof(temp_path), "%s", prog_path);
    char *dir = dirname(temp_path);
    
    // Construct path relative to binary directory
    snprintf(out_path, max_len, "%s/%s", dir, target_filename);
    
    // Fallback check if file exists
    struct stat st;
    if (stat(out_path, &st) != 0) {
        // Fallback to current working directory or generate sandbox
        snprintf(out_path, max_len, "./%s", target_filename);
    }
}

void ensure_sandbox_target(const char *filepath) {
    struct stat st;
    if (stat(filepath, &st) != 0) {
        fprintf(stdout, "[*] Test target '%s' missing. Generating automated sandbox image...\n", filepath);
        char cmd[512];
        // Generate a 10MB mock test image using dd
        snprintf(cmd, sizeof(cmd), "dd if=/dev/zero of=\"%s\" bs=1M count=10 status=none", filepath);
        int ret = system(cmd);
        if (ret != 0) {
            fprintf(stderr, "[!] Warning: Failed to automatically create sandbox target via dd.\n");
        } else {
            fprintf(stdout, "[+] Successfully generated sandbox target: %s\n", filepath);
        }
    }
}

void test_image_gen_destroy(SyntheticEvidenceImage *img) {
    if (!img) return;

    for (size_t i = 0; i < img->record_count; i++) {
        if (img->records[i].actual_blocks) {
            free(img->records[i].actual_blocks);
        }
    }
    
    if (img->records) {
        free(img->records);
        img->records = NULL;
    }
    
    if (img->data) {
        OPENSSL_cleanse(img->data, img->image_size);
        free(img->data);
        img->data = NULL;
    }
}

static void compute_sha256(const void *data, size_t len, char out[65]) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(data, len, hash);
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(out + (i * 2), "%02x", hash[i]);
    }
    out[64] = 0;
}

ErasecureError test_image_gen_embed_file(SyntheticEvidenceImage *img, const char *file_name, const void *data, size_t data_len, FragPattern pattern, GroundTruthRecord *record_out) {
    if (!img || !file_name || !data || data_len == 0) return ERR_INVALID_PARAM;

    size_t blocks_needed = (data_len + img->block_size - 1) / img->block_size;
    if (img->next_free_block + blocks_needed > img->total_blocks) return ERR_FILESYSTEM;

    GroundTruthRecord rec;
    memset(&rec, 0, sizeof(rec));
    strncpy(rec.name, file_name, sizeof(rec.name) - 1);
    rec.original_size = data_len;
    rec.block_count = blocks_needed;
    rec.pattern_used = pattern;
    compute_sha256(data, data_len, rec.sha256);
    
    rec.actual_blocks = calloc(blocks_needed, sizeof(uint64_t));
    if (!rec.actual_blocks) return ERR_MEMORY_ALLOCATION_FAILED;

    const uint8_t *ptr = data;
    
    if (pattern == FRAG_PATTERN_CONTIGUOUS) {
        rec.start_block = img->next_free_block;
        for (size_t i = 0; i < blocks_needed; i++) {
            rec.actual_blocks[i] = img->next_free_block++;
            size_t copy_len = (i == blocks_needed - 1 && data_len % img->block_size != 0) ? (data_len % img->block_size) : img->block_size;
            memcpy(img->data + (rec.actual_blocks[i] * img->block_size), ptr, copy_len);
            ptr += copy_len;
        }
    } else if (pattern == FRAG_PATTERN_GAP) {
        rec.start_block = img->next_free_block;
        size_t half = blocks_needed / 2;
        for (size_t i = 0; i < blocks_needed; i++) {
            if (i == half) img->next_free_block += 2; /* 2 block gap */
            rec.actual_blocks[i] = img->next_free_block++;
            size_t copy_len = (i == blocks_needed - 1 && data_len % img->block_size != 0) ? (data_len % img->block_size) : img->block_size;
            memcpy(img->data + (rec.actual_blocks[i] * img->block_size), ptr, copy_len);
            ptr += copy_len;
        }
    } else {
        // Fallback to contiguous for others for now
        rec.start_block = img->next_free_block;
        for (size_t i = 0; i < blocks_needed; i++) {
            rec.actual_blocks[i] = img->next_free_block++;
            size_t copy_len = (i == blocks_needed - 1 && data_len % img->block_size != 0) ? (data_len % img->block_size) : img->block_size;
            memcpy(img->data + (rec.actual_blocks[i] * img->block_size), ptr, copy_len);
            ptr += copy_len;
        }
    }

    if (img->record_count >= img->record_capacity) {
        size_t new_cap = img->record_capacity * 2;
        GroundTruthRecord *new_recs = realloc(img->records, new_cap * sizeof(GroundTruthRecord));
        if (!new_recs) {
            free(rec.actual_blocks);
            return ERR_MEMORY_ALLOCATION_FAILED;
        }
        img->records = new_recs;
        img->record_capacity = new_cap;
    }
    
    img->records[img->record_count++] = rec;
    
    if (record_out) *record_out = rec;
    
    return ERR_SUCCESS;
}

ErasecureError test_image_gen_write(const SyntheticEvidenceImage *img) {
    if (!img) return ERR_INVALID_PARAM;
    
    FILE *f = fopen(img->image_path, "wb");
    if (!f) return ERR_IO_WRITE;
    
    size_t written = fwrite(img->data, 1, img->image_size, f);
    fclose(f);
    
    if (written != img->image_size) return ERR_IO_WRITE;
    return ERR_SUCCESS;
}
