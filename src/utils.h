#ifndef UTILS_H
#define UTILS_H

#include <errno.h>
#include <fcntl.h> // open()
#include <pthread.h>
#include <unistd.h> // close()
/* play MP3 files */
#include <ao/ao.h>
#include <mpg123.h>

#include "queue.h"

extern const char *sound_repository_path;

int play_sound(const char *sound_path);

void *handle_sound_name_queue();

bool is_file_accessible(const char *file_path);

#endif /* UTILS_H */
