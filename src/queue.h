#ifndef QUEUE_H
#define QUEUE_H

#include <stdlib.h>

#define MAX_SOUND_QUEUE_SIZE 32

/**
 * This function is not thread-safe and should only be called once.
 * If pacq_initialize_queue() call is successful, users need to call
 * pacq_finalize_queue() to release resources.
 * @returns 0 if the queue is successfully initialized or a error code on error
 */
int pacq_initialize_queue();

ssize_t pacq_get_queue_size();

/**
 * @returns 0 if a sound_name is successfully enqueued or a negative number on
 * error
 */
int pacq_enqueue(const char *sound_name);

/**
 * @returns Return a pointer to sound_name at front_ptr or NULL in case of empty
 * queue or memory allocation failure. Caller needs to free() the char pointer
 * after use.
 */
char *pacq_peek();

int pacq_dequeue();

void pacq_finalize_queue();

#endif /* QUEUE_H */
