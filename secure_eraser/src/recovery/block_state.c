#include "recovery/block_state.h"
#include <stdlib.h>
#include <string.h>

#define BLOCK_STATE_MAGIC 0x424C4B53 // "BLKS"

ErasecureError block_state_create(BlockState *bs, uint64_t block_number) {
    if (!bs) return ERASECURE_ERR_INVALID_ARG;
    
    memset(bs, 0, sizeof(BlockState));
    bs->block_number = block_number;
    bs->confidence = 0;
    bs->validation = BLOCK_VALIDATION_UNKNOWN;
    return 0;
}

void block_state_free(BlockState *bs) {
    if (bs) {
        if (bs->format_data) {
            free(bs->format_data);
        }
        memset(bs, 0, sizeof(BlockState));
    }
}

ErasecureError block_state_set_format_data(BlockState *bs, const void *data, size_t len) {
    if (!bs || (!data && len > 0)) return ERASECURE_ERR_INVALID_ARG;
    
    if (bs->format_data) {
        free(bs->format_data);
        bs->format_data = NULL;
    }
    
    bs->format_data_len = len;
    if (len > 0) {
        bs->format_data = malloc(len);
        if (!bs->format_data) return ERASECURE_ERR_NO_MEM;
        memcpy(bs->format_data, data, len);
    }
    return 0;
}

ErasecureError block_state_get_format_data(const BlockState *bs, void *out_data, size_t *out_len) {
    if (!bs || !out_len) return ERASECURE_ERR_INVALID_ARG;
    
    *out_len = bs->format_data_len;
    if (out_data && bs->format_data_len > 0) {
        memcpy(out_data, bs->format_data, bs->format_data_len);
    }
    return 0;
}

ErasecureError block_state_serialize(const BlockState *bs, void *buf, size_t buf_len, size_t *written) {
    if (!bs || !buf || !written) return ERASECURE_ERR_INVALID_ARG;
    
    size_t required = sizeof(uint32_t) + sizeof(uint64_t) + sizeof(uint32_t) + 
                      sizeof(uint32_t) + 32 + sizeof(uint64_t) + sizeof(uint32_t) + 
                      sizeof(uint8_t) + sizeof(uint64_t) + bs->format_data_len;
                      
    if (buf_len < required) return ERASECURE_ERR_INVALID_ARG;
    
    uint8_t *ptr = (uint8_t *)buf;
    uint32_t magic = BLOCK_STATE_MAGIC;
    
    memcpy(ptr, &magic, sizeof(magic)); ptr += sizeof(magic);
    memcpy(ptr, &bs->block_number, sizeof(bs->block_number)); ptr += sizeof(bs->block_number);
    memcpy(ptr, &bs->confidence, sizeof(bs->confidence)); ptr += sizeof(bs->confidence);
    uint32_t val = bs->validation;
    memcpy(ptr, &val, sizeof(val)); ptr += sizeof(val);
    memcpy(ptr, bs->file_type, 32); ptr += 32;
    memcpy(ptr, &bs->offset_in_file, sizeof(bs->offset_in_file)); ptr += sizeof(bs->offset_in_file);
    memcpy(ptr, &bs->crc32, sizeof(bs->crc32)); ptr += sizeof(bs->crc32);
    uint8_t cv = bs->crc_valid ? 1 : 0;
    memcpy(ptr, &cv, sizeof(cv)); ptr += sizeof(cv);
    
    uint64_t fd_len = bs->format_data_len;
    memcpy(ptr, &fd_len, sizeof(fd_len)); ptr += sizeof(fd_len);
    
    if (fd_len > 0) {
        memcpy(ptr, bs->format_data, fd_len); ptr += fd_len;
    }
    
    *written = (size_t)(ptr - (uint8_t *)buf);
    return 0;
}

ErasecureError block_state_deserialize(BlockState *bs, const void *buf, size_t buf_len) {
    if (!bs || !buf || buf_len < 4) return ERASECURE_ERR_INVALID_ARG;
    
    const uint8_t *ptr = (const uint8_t *)buf;
    uint32_t magic;
    memcpy(&magic, ptr, sizeof(magic)); ptr += sizeof(magic);
    
    if (magic != BLOCK_STATE_MAGIC) return ERASECURE_ERR_INVALID_ARG;
    
    block_state_free(bs);
    memset(bs, 0, sizeof(BlockState));
    
    memcpy(&bs->block_number, ptr, sizeof(bs->block_number)); ptr += sizeof(bs->block_number);
    memcpy(&bs->confidence, ptr, sizeof(bs->confidence)); ptr += sizeof(bs->confidence);
    uint32_t val;
    memcpy(&val, ptr, sizeof(val)); ptr += sizeof(val);
    bs->validation = (BlockValidation)val;
    
    memcpy(bs->file_type, ptr, 32); ptr += 32;
    memcpy(&bs->offset_in_file, ptr, sizeof(bs->offset_in_file)); ptr += sizeof(bs->offset_in_file);
    memcpy(&bs->crc32, ptr, sizeof(bs->crc32)); ptr += sizeof(bs->crc32);
    uint8_t cv;
    memcpy(&cv, ptr, sizeof(cv)); ptr += sizeof(cv);
    bs->crc_valid = (cv != 0);
    
    uint64_t fd_len;
    memcpy(&fd_len, ptr, sizeof(fd_len)); ptr += sizeof(fd_len);
    
    if (fd_len > 0) {
        if ((size_t)((ptr + fd_len) - (const uint8_t *)buf) > buf_len) return ERASECURE_ERR_INVALID_ARG;
        bs->format_data = malloc(fd_len);
        if (!bs->format_data) return ERASECURE_ERR_NO_MEM;
        memcpy(bs->format_data, ptr, fd_len);
        bs->format_data_len = fd_len;
    }
    
    return 0;
}
