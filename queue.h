#ifndef QUEUE_H
#define QUEUE_H

#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define MAX_SOUND_QUEUE_SIZE 2048

int initialize_queue();

int get_queue_size();

/**
 * @brief Caller needs to free() the returned char pointer
 * 
 */
char* list_queue_items();

bool enqueue(const char* sound_name);

/**
 * Return a pointer to sound_name at front_ptr or NULL in case of empty queue or memory allocation failure.
 * Caller needs to free() the char pointer after use.
*/
char* peek();

void dequeue();

void finalize_queue();

#endif /* QUEUE_H */