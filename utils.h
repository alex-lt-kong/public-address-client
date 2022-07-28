#ifndef UTILS_H
#define UTILS_H

#include <onion/log.h>
#include <pthread.h>
/* play MP3 files */
#include <ao/ao.h>
#include <mpg123.h>

#include "queue.h"

extern const char* sound_repository_path;
extern pthread_mutex_t lock;

int play_sound(const char* sound_path);

void* handle_sound_name_queue();

#endif /* QUEUE_H */