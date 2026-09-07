#include "recovery/recovery_output.h"
#include <stdio.h>
#include <string.h>

ErasecureError recovery_output_init(const char *base_dir) {
    if (!base_dir) return ERASECURE_ERR_INVALID_ARG;
    /* Implementation to create subdirectories */
    return ERASECURE_SUCCESS;
}

ErasecureError recovery_output_write_file(const char *base_dir, const char *category, const char *ext, const void *data, size_t len, const RecoveredFileMetadata *meta, char *path_out, size_t path_out_len) {
    if (!base_dir || !category || !ext || !data || !meta || !path_out) return ERASECURE_ERR_INVALID_ARG;
    
    snprintf(path_out, path_out_len, "%s/%s/%s.%s", base_dir, category, meta->uuid, ext);
    FILE *f = fopen(path_out, "wb");
    if (!f) return ERASECURE_ERR_IO;
    
    if (len > 0) {
        if (fwrite(data, 1, len, f) != len) {
            fclose(f);
            return ERASECURE_ERR_IO;
        }
    }
    
    fclose(f);
    return ERASECURE_SUCCESS;
}

ErasecureError recovery_output_write_manifest(const char *base_dir, const RecoveredFileMetadata *meta) {
    if (!base_dir || !meta) return ERASECURE_ERR_INVALID_ARG;
    
    char manifest_path[1024];
    snprintf(manifest_path, sizeof(manifest_path), "%s/manifest.jsonl", base_dir);
    FILE *f = fopen(manifest_path, "a");
    if (!f) return ERASECURE_ERR_IO;
    
    fprintf(f, "{\"uuid\":\"%s\",\"file_type\":\"%s\",\"size_bytes\":%llu,\"sha256\":\"%s\",\"confidence\":%u,\"start_block\":%llu,\"block_count\":%llu,\"output_path\":\"%s\"}\n",
            meta->uuid, meta->file_type, (unsigned long long)meta->size_bytes, meta->sha256, meta->confidence, (unsigned long long)meta->start_block, (unsigned long long)meta->block_count, meta->output_path);
    fclose(f);
    
    return ERASECURE_SUCCESS;
}
