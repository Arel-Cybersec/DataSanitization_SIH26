#ifndef ERASECURE_BLOCKVECTOR_H
#define ERASECURE_BLOCKVECTOR_H

#include "common/types.h"
#include "common/error.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

typedef struct {
    uint64_t apparent_block;   /* Position in apparent image */
    uint64_t actual_block;     /* Position in actual/physical image */
    bool     valid;            /* Whether this slot has been validated */
    bool     tried;            /* Whether this choice was already tried and backtracked */
} BvSlot;

struct Blockvector {
    BvSlot  *slots;           /* Dynamic array of block slots */
    size_t   length;          /* Current number of slots */
    size_t   capacity;        /* Allocated capacity */
};

/**
 * @brief Initialize a new blockvector with initial capacity.
 */
ErasecureError blockvector_create(Blockvector *bv, size_t initial_capacity);

/**
 * @brief Free resources associated with a blockvector.
 */
void blockvector_free(Blockvector *bv);

/**
 * @brief Append a block slot to the vector.
 */
ErasecureError blockvector_append(Blockvector *bv, uint64_t apparent_block, uint64_t actual_block);

/**
 * @brief Remove the last block slot from the vector.
 */
ErasecureError blockvector_remove_last(Blockvector *bv);

/**
 * @brief Get a block slot by index.
 */
const BvSlot *blockvector_get(const Blockvector *bv, size_t index);

/**
 * @brief Mark a specific block slot as tried (backtracked).
 */
ErasecureError blockvector_mark_tried(Blockvector *bv, size_t index);

/**
 * @brief Mark a specific block slot as valid.
 */
ErasecureError blockvector_mark_valid(Blockvector *bv, size_t index);

/**
 * @brief Trim the blockvector to a specified length.
 */
ErasecureError blockvector_restore(Blockvector *bv, size_t length);

/**
 * @brief Clone a blockvector deeply.
 */
ErasecureError blockvector_clone(const Blockvector *src, Blockvector *dst);

/**
 * @brief Get the current length of the blockvector.
 */
size_t blockvector_length(const Blockvector *bv);

#endif /* ERASECURE_BLOCKVECTOR_H */
