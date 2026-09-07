#include "recovery/worker_pool.h"
#include <pthread.h>
#include <stdlib.h>
#include <stdbool.h>

typedef struct WorkerTask {
    WorkerTaskFn fn;
    void *arg;
} WorkerTask;

struct WorkerPool {
    pthread_t *threads;
    size_t num_threads;
    WorkerTask *queue;
    size_t queue_size;
    size_t head;
    size_t tail;
    size_t count;
    bool shutdown;
    size_t active_tasks;
    pthread_mutex_t lock;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
    pthread_cond_t is_idle;
};

static void *worker_thread(void *arg) {
    WorkerPool *pool = (WorkerPool *)arg;
    while (1) {
        pthread_mutex_lock(&pool->lock);
        while (pool->count == 0 && !pool->shutdown) {
            pthread_cond_wait(&pool->not_empty, &pool->lock);
        }
        if (pool->shutdown && pool->count == 0) {
            pthread_mutex_unlock(&pool->lock);
            break;
        }
        WorkerTask task = pool->queue[pool->head];
        pool->head = (pool->head + 1) % pool->queue_size;
        pool->count--;
        pool->active_tasks++;
        pthread_cond_signal(&pool->not_full);
        pthread_mutex_unlock(&pool->lock);
        
        if (task.fn) {
            task.fn(task.arg);
        }
        
        pthread_mutex_lock(&pool->lock);
        pool->active_tasks--;
        if (pool->count == 0 && pool->active_tasks == 0) {
            pthread_cond_signal(&pool->is_idle);
        }
        pthread_mutex_unlock(&pool->lock);
    }
    return NULL;
}

WorkerPool *worker_pool_create(size_t num_threads, size_t max_queue_size) {
    if (num_threads == 0 || max_queue_size == 0) return NULL;
    WorkerPool *pool = malloc(sizeof(WorkerPool));
    if (!pool) return NULL;
    pool->num_threads = num_threads;
    pool->queue_size = max_queue_size;
    pool->head = pool->tail = pool->count = pool->active_tasks = 0;
    pool->shutdown = false;
    
    pool->queue = malloc(sizeof(WorkerTask) * max_queue_size);
    if (!pool->queue) {
        free(pool);
        return NULL;
    }
    
    pool->threads = malloc(sizeof(pthread_t) * num_threads);
    if (!pool->threads) {
        free(pool->queue);
        free(pool);
        return NULL;
    }
    
    pthread_mutex_init(&pool->lock, NULL);
    pthread_cond_init(&pool->not_empty, NULL);
    pthread_cond_init(&pool->not_full, NULL);
    pthread_cond_init(&pool->is_idle, NULL);
    
    for (size_t i = 0; i < num_threads; i++) {
        pthread_create(&pool->threads[i], NULL, worker_thread, pool);
    }
    return pool;
}

void worker_pool_destroy(WorkerPool *pool) {
    if (!pool) return;
    pthread_mutex_lock(&pool->lock);
    pool->shutdown = true;
    pthread_cond_broadcast(&pool->not_empty);
    pthread_mutex_unlock(&pool->lock);
    
    for (size_t i = 0; i < pool->num_threads; i++) {
        pthread_join(pool->threads[i], NULL);
    }
    
    pthread_mutex_destroy(&pool->lock);
    pthread_cond_destroy(&pool->not_empty);
    pthread_cond_destroy(&pool->not_full);
    pthread_cond_destroy(&pool->is_idle);
    
    free(pool->threads);
    free(pool->queue);
    free(pool);
}

ErasecureError worker_pool_submit(WorkerPool *pool, WorkerTaskFn task, void *arg) {
    if (!pool || !task) return ERASECURE_ERR_INVALID_ARG;
    pthread_mutex_lock(&pool->lock);
    while (pool->count == pool->queue_size && !pool->shutdown) {
        pthread_cond_wait(&pool->not_full, &pool->lock);
    }
    if (pool->shutdown) {
        pthread_mutex_unlock(&pool->lock);
        return ERASECURE_ERR_GENERIC;
    }
    pool->queue[pool->tail].fn = task;
    pool->queue[pool->tail].arg = arg;
    pool->tail = (pool->tail + 1) % pool->queue_size;
    pool->count++;
    pthread_cond_signal(&pool->not_empty);
    pthread_mutex_unlock(&pool->lock);
    return ERASECURE_SUCCESS;
}

void worker_pool_wait_idle(WorkerPool *pool) {
    if (!pool) return;
    pthread_mutex_lock(&pool->lock);
    while (pool->count > 0 || pool->active_tasks > 0) {
        pthread_cond_wait(&pool->is_idle, &pool->lock);
    }
    pthread_mutex_unlock(&pool->lock);
}
