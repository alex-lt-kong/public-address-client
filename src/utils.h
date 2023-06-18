#ifndef UTILS_H
#define UTILS_H

#include <errno.h>
#include <fcntl.h> // open()
#include <onion/codecs.h>
#include <onion/log.h>
#include <onion/onion.h>
#include <pthread.h>
#include <unistd.h> // close()
/* play MP3 files */
#include <ao/ao.h>
#include <mpg123.h>

#include "queue.h"

extern const char *sound_repository_path;
extern const char *pac_username;
extern const char *pac_passwd;
extern pthread_mutex_t lock;

/**
 * @brief If a request is authenticated, neither request nor response will be
 * modified, the caller should do whatever it wants as if such authentication
 * has never happened. If a request is not authenticated, proper response has
 * been written to res, caller should just return OCS_PROCESSED to its caller.
 */
bool authenticate(onion_request *req, onion_response *res);

int play_sound(const char *sound_path);

void *handle_sound_name_queue();

bool is_file_accessible(const char *file_path);

#endif /* UTILS_H */
