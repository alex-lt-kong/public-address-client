#ifndef QUEUE_H
#define QUEUE_H

#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_SOUND_QUEUE_SIZE 8

// This function is not thread-safe and should only be called once
int initialize_queue();

ssize_t get_queue_size();

/**
 * @returns 0 if a sound_name is successfully enqueued or a negative number on
 * error
 */
int enqueue(const char *sound_name);

/**
 * Return a pointer to sound_name at front_ptr or NULL in case of empty queue or
 * memory allocation failure. Caller needs to free() the char pointer after use.
 */
char *peek();

int dequeue();

void finalize_queue();

#endif /* QUEUE_H */
