#ifndef UTILS_H
#define UTILS_H

#include "queue.h"

#include <errno.h>
#include <fcntl.h> // open()
#include <pthread.h>
#include <stdbool.h>
#include <unistd.h> // close()
/* play MP3 files */
#include <ao/ao.h>
#include <mpg123.h>

extern const char *sound_repository_path;
extern const char *http_auth_username;
extern const char *http_auth_password;

int play_sound(const char *sound_path);

void *handle_sound_name_queue();

bool is_file_accessible(const char *file_path);

#endif /* UTILS_H */
