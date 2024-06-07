#ifndef UTILS_H
#define UTILS_H

#include <json-c/json.h> /* JSON */
/* play MP3 files */
#include <ao/ao.h>
#include <mpg123.h>

#include <errno.h>
#include <fcntl.h> // open()
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <unistd.h> // close()

#define PROGRAM_NAME "public-address-client"
#define SSL_FILE_BUFF_SIZE 8192

extern char gv_sound_repository_path[];
extern char gv_http_auth_username[];
extern char http_auth_password[];
extern char gv_interface[];
// gv_ssl_key and gv_ssl_crt are string, not bytes
extern char gv_ssl_key[SSL_FILE_BUFF_SIZE];
extern char gv_ssl_crt[SSL_FILE_BUFF_SIZE];
extern int gv_port;

int play_sound(const char *sound_path);

void *handle_sound_name_queue();

bool is_file_accessible(const char *file_path);

/**
 * @returns returns 0 on success, or a non-zero number indicating error type
 */
int load_values_from_json(const char *settings_path);

#endif /* UTILS_H */
