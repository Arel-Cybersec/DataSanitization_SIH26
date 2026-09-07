#ifndef ERASECURE_WORKER_POOL_H
#define ERASECURE_WORKER_POOL_H

#include <stddef.h>
#include "common/error.h"

typedef void (*WorkerTaskFn)(void *arg);

typedef struct WorkerPool WorkerPool;

/**
 * @brief Create a worker pool.
 *
 * @param num_threads Number of threads in the pool.
 * @param max_queue_size Maximum size of the task queue.
 * @return WorkerPool* Pointer to created pool or NULL.
 */
WorkerPool *worker_pool_create(size_t num_threads, size_t max_queue_size);

/**
 * @brief Destroy a worker pool and free its resources.
 *
 * @param pool Pointer to the WorkerPool.
 */
void worker_pool_destroy(WorkerPool *pool);

/**
 * @brief Submit a task to the worker pool.
 *
 * @param pool Pointer to the WorkerPool.
 * @param task The task function to execute.
 * @param arg Arguments to pass to the task function.
 * @return ErasecureError Success or error code.
 */
ErasecureError worker_pool_submit(WorkerPool *pool, WorkerTaskFn task, void *arg);

/**
 * @brief Wait for all submitted tasks to complete.
 *
 * @param pool Pointer to the WorkerPool.
 */
void worker_pool_wait_idle(WorkerPool *pool);

#endif /* ERASECURE_WORKER_POOL_H */
