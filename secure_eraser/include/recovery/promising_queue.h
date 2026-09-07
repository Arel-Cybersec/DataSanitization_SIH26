#ifndef ERASECURE_PROMISING_QUEUE_H
#define ERASECURE_PROMISING_QUEUE_H

#include "common/types.h"
#include "common/error.h"
#include "recovery/carve_state.h"
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>

typedef struct {
    CarveState **entries;       /* Array of pointers to candidates */
    size_t       count;
    size_t       capacity;
    pthread_mutex_t lock;
    pthread_cond_t  not_empty;
    bool         shutdown;      /* Signal workers to stop */
} PromisingQueue;

ErasecureError promising_queue_init(PromisingQueue *pq, size_t initial_capacity);
void promising_queue_destroy(PromisingQueue *pq);
ErasecureError promising_queue_enqueue(PromisingQueue *pq, CarveState *candidate);
ErasecureError promising_queue_dequeue(PromisingQueue *pq, CarveState **out);
ErasecureError promising_queue_requeue(PromisingQueue *pq, CarveState *candidate);
ErasecureError promising_queue_remove(PromisingQueue *pq, const char *uuid);
ErasecureError promising_queue_kill(PromisingQueue *pq, const char *uuid);
ErasecureError promising_queue_update_priority(PromisingQueue *pq, const char *uuid, uint32_t new_priority);
size_t promising_queue_size(const PromisingQueue *pq);
bool promising_queue_is_empty(const PromisingQueue *pq);
void promising_queue_shutdown(PromisingQueue *pq);

#endif
