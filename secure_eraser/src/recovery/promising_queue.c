#include "recovery/promising_queue.h"
#include <stdlib.h>
#include <string.h>

/**
 * @brief Initialize a promising queue.
 */
ErasecureError promising_queue_init(PromisingQueue *pq, size_t initial_capacity) {
    if (!pq) return ERASECURE_ERROR_INVALID_ARGUMENT;
    pq->capacity = initial_capacity > 0 ? initial_capacity : 16;
    pq->count = 0;
    pq->shutdown = false;
    pq->entries = malloc(pq->capacity * sizeof(CarveState*));
    if (!pq->entries) return ERASECURE_ERROR_MEMORY;
    pthread_mutex_init(&pq->lock, NULL);
    pthread_cond_init(&pq->not_empty, NULL);
    return ERASECURE_SUCCESS;
}

/**
 * @brief Destroy a promising queue.
 */
void promising_queue_destroy(PromisingQueue *pq) {
    if (!pq) return;
    pthread_mutex_lock(&pq->lock);
    pq->shutdown = true;
    pthread_cond_broadcast(&pq->not_empty);
    pthread_mutex_unlock(&pq->lock);
    
    // Wait for callers to handle shutdown...
    
    pthread_mutex_destroy(&pq->lock);
    pthread_cond_destroy(&pq->not_empty);
    free(pq->entries);
    pq->entries = NULL;
}

/**
 * Heap helper functions
 */
static void swap(CarveState **a, CarveState **b) {
    CarveState *tmp = *a;
    *a = *b;
    *b = tmp;
}

static void heapify_up(PromisingQueue *pq, size_t index) {
    while (index > 0) {
        size_t parent = (index - 1) / 2;
        // Compare priority (assuming CarveState has a uint32_t priority field)
        // Note: The CarveState struct definition isn't fully provided, we assume priority exists
        if (pq->entries[index]->priority < pq->entries[parent]->priority) {
            swap(&pq->entries[index], &pq->entries[parent]);
            index = parent;
        } else {
            break;
        }
    }
}

static void heapify_down(PromisingQueue *pq, size_t index) {
    while (true) {
        size_t left = 2 * index + 1;
        size_t right = 2 * index + 2;
        size_t smallest = index;

        if (left < pq->count && pq->entries[left]->priority < pq->entries[smallest]->priority)
            smallest = left;
        if (right < pq->count && pq->entries[right]->priority < pq->entries[smallest]->priority)
            smallest = right;

        if (smallest != index) {
            swap(&pq->entries[index], &pq->entries[smallest]);
            index = smallest;
        } else {
            break;
        }
    }
}

/**
 * @brief Enqueue a candidate.
 */
ErasecureError promising_queue_enqueue(PromisingQueue *pq, CarveState *candidate) {
    if (!pq || !candidate) return ERASECURE_ERROR_INVALID_ARGUMENT;
    
    pthread_mutex_lock(&pq->lock);
    if (pq->shutdown) {
        pthread_mutex_unlock(&pq->lock);
        return ERASECURE_ERROR_INVALID_STATE; // Or some other code indicating shutdown
    }
    
    if (pq->count == pq->capacity) {
        size_t new_cap = pq->capacity * 2;
        CarveState **new_entries = realloc(pq->entries, new_cap * sizeof(CarveState*));
        if (!new_entries) {
            pthread_mutex_unlock(&pq->lock);
            return ERASECURE_ERROR_MEMORY;
        }
        pq->entries = new_entries;
        pq->capacity = new_cap;
    }
    
    pq->entries[pq->count] = candidate;
    heapify_up(pq, pq->count);
    pq->count++;
    
    pthread_cond_signal(&pq->not_empty);
    pthread_mutex_unlock(&pq->lock);
    
    return ERASECURE_SUCCESS;
}

/**
 * @brief Dequeue the highest priority candidate.
 */
ErasecureError promising_queue_dequeue(PromisingQueue *pq, CarveState **out) {
    if (!pq || !out) return ERASECURE_ERROR_INVALID_ARGUMENT;
    
    pthread_mutex_lock(&pq->lock);
    while (pq->count == 0 && !pq->shutdown) {
        pthread_cond_wait(&pq->not_empty, &pq->lock);
    }
    
    if (pq->shutdown && pq->count == 0) {
        pthread_mutex_unlock(&pq->lock);
        return ERASECURE_ERROR_NOT_FOUND; // Using NOT_FOUND as empty marker for now
    }
    
    *out = pq->entries[0];
    pq->entries[0] = pq->entries[pq->count - 1];
    pq->count--;
    
    if (pq->count > 0) {
        heapify_down(pq, 0);
    }
    
    pthread_mutex_unlock(&pq->lock);
    return ERASECURE_SUCCESS;
}

/**
 * @brief Requeue an existing candidate (adds back into queue).
 */
ErasecureError promising_queue_requeue(PromisingQueue *pq, CarveState *candidate) {
    return promising_queue_enqueue(pq, candidate);
}

/**
 * @brief Remove a specific candidate by UUID.
 */
ErasecureError promising_queue_remove(PromisingQueue *pq, const char *uuid) {
    if (!pq || !uuid) return ERASECURE_ERROR_INVALID_ARGUMENT;
    
    pthread_mutex_lock(&pq->lock);
    for (size_t i = 0; i < pq->count; i++) {
        if (strcmp(pq->entries[i]->uuid, uuid) == 0) {
            pq->entries[i] = pq->entries[pq->count - 1];
            pq->count--;
            if (i < pq->count) {
                heapify_down(pq, i);
                heapify_up(pq, i);
            }
            pthread_mutex_unlock(&pq->lock);
            return ERASECURE_SUCCESS;
        }
    }
    pthread_mutex_unlock(&pq->lock);
    return ERASECURE_ERROR_NOT_FOUND;
}

/**
 * @brief Remove and potentially free a candidate.
 */
ErasecureError promising_queue_kill(PromisingQueue *pq, const char *uuid) {
    // For now, equivalent to remove. The caller must free if necessary.
    return promising_queue_remove(pq, uuid);
}

/**
 * @brief Update candidate priority.
 */
ErasecureError promising_queue_update_priority(PromisingQueue *pq, const char *uuid, uint32_t new_priority) {
    if (!pq || !uuid) return ERASECURE_ERROR_INVALID_ARGUMENT;
    
    pthread_mutex_lock(&pq->lock);
    for (size_t i = 0; i < pq->count; i++) {
        if (strcmp(pq->entries[i]->uuid, uuid) == 0) {
            pq->entries[i]->priority = new_priority;
            heapify_down(pq, i);
            heapify_up(pq, i);
            pthread_mutex_unlock(&pq->lock);
            return ERASECURE_SUCCESS;
        }
    }
    pthread_mutex_unlock(&pq->lock);
    return ERASECURE_ERROR_NOT_FOUND;
}

/**
 * @brief Get queue size.
 */
size_t promising_queue_size(const PromisingQueue *pq) {
    if (!pq) return 0;
    pthread_mutex_lock((pthread_mutex_t*)&pq->lock);
    size_t sz = pq->count;
    pthread_mutex_unlock((pthread_mutex_t*)&pq->lock);
    return sz;
}

/**
 * @brief Check if empty.
 */
bool promising_queue_is_empty(const PromisingQueue *pq) {
    return promising_queue_size(pq) == 0;
}

/**
 * @brief Shutdown queue.
 */
void promising_queue_shutdown(PromisingQueue *pq) {
    if (!pq) return;
    pthread_mutex_lock(&pq->lock);
    pq->shutdown = true;
    pthread_cond_broadcast(&pq->not_empty);
    pthread_mutex_unlock(&pq->lock);
}
