#include "recovery/blockvector.h"
#include <stdlib.h>
#include <string.h>

ErasecureError blockvector_create(Blockvector *bv, size_t initial_capacity) {
    if (!bv) return ERASECURE_ERR_INVALID_ARG;
    
    bv->length = 0;
    bv->capacity = initial_capacity > 0 ? initial_capacity : 16;
    bv->slots = calloc(bv->capacity, sizeof(BvSlot));
    
    if (!bv->slots) return ERASECURE_ERR_NO_MEM;
    return 0;
}

void blockvector_free(Blockvector *bv) {
    if (bv) {
        if (bv->slots) {
            free(bv->slots);
        }
        memset(bv, 0, sizeof(Blockvector));
    }
}

ErasecureError blockvector_append(Blockvector *bv, uint64_t apparent_block, uint64_t actual_block) {
    if (!bv) return ERASECURE_ERR_INVALID_ARG;
    
    if (bv->length >= bv->capacity) {
        size_t new_capacity = bv->capacity * 2;
        if (new_capacity == 0) new_capacity = 16;
        
        BvSlot *new_slots = realloc(bv->slots, new_capacity * sizeof(BvSlot));
        if (!new_slots) return ERASECURE_ERR_NO_MEM;
        
        bv->slots = new_slots;
        bv->capacity = new_capacity;
    }
    
    BvSlot *slot = &bv->slots[bv->length++];
    slot->apparent_block = apparent_block;
    slot->actual_block = actual_block;
    slot->valid = false;
    slot->tried = false;
    
    return 0;
}

ErasecureError blockvector_remove_last(Blockvector *bv) {
    if (!bv || bv->length == 0) return ERASECURE_ERR_INVALID_ARG;
    bv->length--;
    return 0;
}

const BvSlot *blockvector_get(const Blockvector *bv, size_t index) {
    if (!bv || index >= bv->length) return NULL;
    return &bv->slots[index];
}

ErasecureError blockvector_mark_tried(Blockvector *bv, size_t index) {
    if (!bv || index >= bv->length) return ERASECURE_ERR_INVALID_ARG;
    bv->slots[index].tried = true;
    return 0;
}

ErasecureError blockvector_mark_valid(Blockvector *bv, size_t index) {
    if (!bv || index >= bv->length) return ERASECURE_ERR_INVALID_ARG;
    bv->slots[index].valid = true;
    return 0;
}

ErasecureError blockvector_restore(Blockvector *bv, size_t length) {
    if (!bv || length > bv->length) return ERASECURE_ERR_INVALID_ARG;
    bv->length = length;
    return 0;
}

ErasecureError blockvector_clone(const Blockvector *src, Blockvector *dst) {
    if (!src || !dst) return ERASECURE_ERR_INVALID_ARG;
    
    ErasecureError err = blockvector_create(dst, src->capacity);
    if (err != 0) return err;
    
    dst->length = src->length;
    if (src->length > 0) {
        memcpy(dst->slots, src->slots, src->length * sizeof(BvSlot));
    }
    
    return 0;
}

size_t blockvector_length(const Blockvector *bv) {
    if (!bv) return 0;
    return bv->length;
}
