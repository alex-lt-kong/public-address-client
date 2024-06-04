#ifndef UTILS_H
#define UTILS_H

#include <json-c/json.h> /* JSON */
/* play MP3 files */
#include <ao/ao.h>
#include <mpg123.h>

#include <errno.h>
#include <fcntl.h> // open()
#include <pthread.h>
#include <stdbool.h>
#include <unistd.h> // close()

#define PROGRAM_NAME "public-address-client"
#define SSL_FILE_BUFF_SIZE 8192

extern const char *sound_repository_path;
extern const char *http_auth_username;
extern const char *http_auth_password;

int play_sound(const char *sound_path);

void *handle_sound_name_queue();

bool is_file_accessible(const char *file_path);

int load_values_from_json(const char *argv0, json_object **json_root_out,
                          const char **out_interface, int *out_port,
                          char **out_ssl_crt, char **out_ssl_key);

#endif /* UTILS_H */
