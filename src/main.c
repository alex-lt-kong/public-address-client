#include <dirent.h> /* Check directory's existence*/
#include <errno.h>
#include <libgen.h> /* dirname() */
#include <linux/limits.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h> /* for waitpid */
#include <unistd.h>

#include <json-c/json.h> /* JSON */
#include <microhttpd.h>

#include "queue.h"
#include "utils.h"

#define RESP_ACCESS_DENIED "Access denied\n"
#define RESP_SERVICE_RUNNING "Client is up and running\n"
#define RESP_NOT_FOUND "Resource not found\n"

#define SSL_FILE_BUFF_SIZE 8192
const char *http_auth_username;
const char *http_auth_password;

static int request_handler(void *cls, struct MHD_Connection *connection,
                           const char *url, const char *method,
                           const char *version, const char *upload_data,
                           size_t *upload_data_size, void **ptr) {
  static int aptr;
  const char *me = cls;
  struct MHD_Response *response;
  int ret;
  char *user;
  char *pass;
  int fail;

  if (0 != strcmp(method, MHD_HTTP_METHOD_GET))
    return MHD_NO; /* unexpected method */
  if (&aptr != *ptr) {
    /* do never respond on first call */
    *ptr = &aptr;
    return MHD_YES;
  }
  *ptr = NULL; /* reset when done */

  pass = NULL;
  user = MHD_basic_auth_get_username_password(connection, &pass);
  fail = ((user == NULL) || (0 != strcmp(user, http_auth_username)) ||
          (0 != strcmp(pass, http_auth_password)));
  char *response_text;
  if (fail) {
    response = MHD_create_response_from_buffer(strlen(RESP_ACCESS_DENIED),
                                               (void *)RESP_ACCESS_DENIED,
                                               MHD_RESPMEM_PERSISTENT);
    ret = MHD_queue_basic_auth_fail_response(connection, "Public Address Realm",
                                             response);
  } else {
    if (strcmp(url, "/health_check/") == 0) {
      response = MHD_create_response_from_buffer(strlen(RESP_SERVICE_RUNNING),
                                                 (void *)RESP_SERVICE_RUNNING,
                                                 MHD_RESPMEM_PERSISTENT);
      ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    } else if (strcmp(url, "/") == 0) {
      const char *sound_name = MHD_lookup_connection_value(
          connection, MHD_GET_ARGUMENT_KIND, "sound_name");
      if (sound_name == NULL) {
        const char err_msg[] = "Parameter sound_name not supplied\n";
        response = MHD_create_response_from_buffer(
            strlen(err_msg), (void *)err_msg, MHD_RESPMEM_MUST_COPY);
        ret = MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, response);
        MHD_destroy_response(response);
        return ret;
      }

      const size_t max_sound_name = 1024;
      response_text =
          malloc(sizeof(char) * strnlen(sound_name, max_sound_name) + 128);
      if (response_text == NULL) {
        const char err_msg[] = "Failed to malloc() memory\n";
        response = MHD_create_response_from_buffer(
            strlen(err_msg), (void *)err_msg, MHD_RESPMEM_MUST_COPY);
        ret = MHD_queue_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                                 response);
        MHD_destroy_response(response);
        return ret;
      }
      if (strstr(sound_name, "/..") != NULL ||
          strstr(sound_name, "../") != NULL) {
        const char err_msg[] =
            "sound_name may try to escape from sound_repository_path\n";
        response = MHD_create_response_from_buffer(
            strlen(err_msg), (void *)err_msg, MHD_RESPMEM_MUST_COPY);
        ret = MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, response);
        MHD_destroy_response(response);
        return ret;
      }

      char sound_path[PATH_MAX] = "", sound_realpath[PATH_MAX];
      strcat(sound_path, sound_repository_path);
      strcat(sound_path, sound_name);
      realpath(sound_path, sound_realpath);
      if (is_file_accessible(sound_realpath) == false) {
        const char err_msg[] = "sound_name is inaccessible\n";
        response = MHD_create_response_from_buffer(
            strlen(err_msg), (void *)err_msg, MHD_RESPMEM_MUST_COPY);
        ret = MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, response);
        MHD_destroy_response(response);
        return ret;
      }

      pthread_mutex_lock(&lock);
      int qs = get_queue_size();
      if (enqueue(sound_realpath)) {
        pthread_mutex_unlock(&lock);
        if (qs == 0) { // i.e., before enqueue() the queue is empty, so we start
                       // a new handle_sound_name_queue thread.
          pthread_t my_thread;
          if (pthread_create(&my_thread, NULL, handle_sound_name_queue, NULL) !=
              0) {
            fprintf(stderr,
                    "Failed to pthread_create() handle_sound_name_queue, "
                    "reason: %s",
                    strerror(errno));
          } else {
            if (pthread_detach(my_thread) != 0)
              fprintf(stderr,
                      "handle_sound_name_queue pthread_create()'ed, but failed "
                      "to pthread_detach() it, reason: %s",
                      my_thread, strerror(errno));
          }
        }

        printf("[%s] added to sound_queue, sound_queue_size: %d", sound_name,
               qs + 1);

        const char msg[] = "added to sound_queue\n";
        response = MHD_create_response_from_buffer(strlen(msg), (void *)msg,
                                                   MHD_RESPMEM_MUST_COPY);
        ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
        MHD_destroy_response(response);
        return ret;
      }
      pthread_mutex_unlock(&lock);
      const char msg[] = "queue is full/server has not enough free memory, "
                         "new sound discarded.";
      ret = MHD_queue_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                               response);
      MHD_destroy_response(response);
      return ret;
    } else {
      response = MHD_create_response_from_buffer(strlen(RESP_NOT_FOUND),
                                                 (void *)RESP_NOT_FOUND,
                                                 MHD_RESPMEM_PERSISTENT);
      ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, response);
    }
  }

  MHD_destroy_response(response);
  return ret;
}

int load_ssl_key_and_crt(const char *crt_path, const char *key_path,
                         char **out_ssl_crt, char **out_ssl_key) {
  FILE *fp;

  fp = fopen(crt_path, "rb");
  if (fp == NULL) {
    fprintf(stderr, "Error: could not open file: '%s'\n", crt_path);
    return -1;
  }

  size_t bytes_read = fread(out_ssl_crt, sizeof(char), SSL_FILE_BUFF_SIZE, fp);
  if (bytes_read > 0) {
  } else if (feof(fp)) {
    fprintf(stderr, "Error: end-of-file reached while reading from file '%s'\n",
            crt_path);
  } else if (ferror(fp)) {
    fprintf(stderr, "Error: error reading from file '%s'\n", crt_path);
    return -1;
  }
  fclose(fp);

  fp = fopen(key_path, "rb");
  if (fp == NULL) {
    fprintf(stderr, "Error: could not open file: '%s'\n", key_path);
    return -1;
  }
  bytes_read = fread(out_ssl_key, sizeof(char), SSL_FILE_BUFF_SIZE, fp);
  if (bytes_read > 0) {
  } else if (feof(fp)) {
    fprintf(stderr, "Error: end-of-file reached while reading from file '%s'\n",
            key_path);
    return -1;
  } else if (ferror(fp)) {
    fprintf(stderr, "Error: error reading from file '%s'\n", key_path);
    return -1;
  }
  fclose(fp);
  return 0;
}

struct MHD_Daemon *init_mhd(const char *interface, const int port,
                            const char *ssl_crt, const char *ssl_key) {

  struct sockaddr_in server_addr;
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(port);
  if (inet_pton(AF_INET, interface, &(server_addr.sin_addr)) < 0) {
    fprintf(stderr, "inet_pton() error: %d(%s)\n", errno, strerror(errno));
    return NULL;
  }

  struct MHD_Daemon *daemon;
  // clang-format off
  daemon = MHD_start_daemon(
                       MHD_USE_SELECT_INTERNALLY | MHD_USE_DEBUG | MHD_USE_TLS,
                       port, NULL,
                       NULL, &request_handler, "",
                       MHD_OPTION_CONNECTION_TIMEOUT, 256,
                       MHD_OPTION_SOCK_ADDR, (struct sockaddr *)&server_addr,
                       MHD_OPTION_HTTPS_MEM_CERT, ssl_crt,
                       MHD_OPTION_HTTPS_MEM_KEY, ssl_key,
                       MHD_OPTION_END);
  // clang-format on
  if (daemon == NULL) {
    fprintf(stderr, "MHD_start_daemon() failed.\n");
    return NULL;
  }
  printf("HTTP server listening on https://%s:%d\n", interface, port);
  return daemon;
}

int check_sound_repo_validity(const char *sound_repository_path) {
  if (sound_repository_path == NULL ||
      strnlen(sound_repository_path, PATH_MAX) >= PATH_MAX / 2) {
    fprintf(stderr, "sound_repository [%s] is either NULL or too long",
            sound_repository_path);
    return -1;
  }
  DIR *dir = opendir(sound_repository_path);
  if (dir) { // exist
    closedir(dir);
  } else {
    fprintf(stderr, "sound_repository [%s] is inaccessible.",
            sound_repository_path);
    return -2;
  }
  return 0;
}

int load_values_from_json(const char *argv0, json_object **json_root_out,
                          char **out_interface, int *out_port,
                          char **out_ssl_crt, char **out_ssl_key) {
  char bin_path[PATH_MAX], settings_path[PATH_MAX] = "";
  if (realpath(argv0, bin_path) == NULL) {
    fprintf(stderr, "realpath() failed: %d(%s)\n", errno, strerror(errno));
    return -1;
  }
  strcpy(settings_path, dirname(bin_path));
  strcat(settings_path, "/settings.json");
  json_object *root = json_object_from_file(settings_path);
  json_object *root_app = json_object_object_get(root, "app");
  json_object *root_app_port = json_object_object_get(root_app, "port");
  json_object *root_app_interface =
      json_object_object_get(root_app, "interface");
  json_object *root_app_sound_repo_path =
      json_object_object_get(root_app, "sound_repo_path");
  json_object *root_app_username = json_object_object_get(root_app, "username");
  json_object *root_app_passwd = json_object_object_get(root_app, "passwd");
  json_object *root_app_ssl = json_object_object_get(root_app, "ssl");
  json_object *root_app_ssl_crt_path =
      json_object_object_get(root_app_ssl, "crt_path");
  json_object *root_app_ssl_key_path =
      json_object_object_get(root_app_ssl, "key_path");
  json_object *root_app_log_path = json_object_object_get(root_app, "log_path");

  sound_repository_path = json_object_get_string(root_app_sound_repo_path);
  if (check_sound_repo_validity(sound_repository_path) < 0) {
    return -2;
  }

  http_auth_username = json_object_get_string(root_app_username);
  http_auth_password = json_object_get_string(root_app_passwd);
  const char *log_path = json_object_get_string(root_app_log_path);
  const char *ssl_crt_path = json_object_get_string(root_app_ssl_crt_path);
  const char *ssl_key_path = json_object_get_string(root_app_ssl_key_path);

  if (log_path == NULL || http_auth_username == NULL ||
      http_auth_password == NULL || ssl_crt_path == NULL ||
      ssl_key_path == NULL) {
    fprintf(stderr, "Some required values are not provided");
    return -3;
  }
  if (load_ssl_key_and_crt(ssl_crt_path, ssl_key_path, out_ssl_crt,
                           out_ssl_key) < 0) {
    fprintf(stderr, "Failed to read either SSL certificate or key\n");
    return -4;
  }
  *out_interface = json_object_get_string(root_app_interface);
  *out_port = atoi(json_object_get_string(root_app_port));
  *json_root_out = root;
  return 0;
}

int main(int argc, char **argv) {
  int retval = 0;

  const char *interface;
  int port;
  char ssl_key[SSL_FILE_BUFF_SIZE];
  char ssl_crt[SSL_FILE_BUFF_SIZE];
  json_object *json_root;
  if (load_values_from_json(argv[0], &json_root, &interface, &port, &ssl_crt,
                            &ssl_key) < 0) {
    retval = -1;
    if (json_root == NULL) {
      goto err_invalid_json;
    }
    goto err_invalid_config;
  }
  retval = pthread_mutex_init(&lock, NULL);
  if (retval != 0) {
    fprintf(stderr, "pthread_mutex_init() failed: %d", retval);
    retval = -1;
    goto err_mutex_init;
  }

  if (initialize_queue() < 0) {
    retval = -1;
    goto err_init_queue;
  }
  struct MHD_Daemon *d = init_mhd(interface, port, ssl_crt, ssl_key);
  if (d == NULL) {
    retval = -1;
    goto err_init_mhd;
  }
  getchar();

  MHD_stop_daemon(d);
err_init_mhd:
  finalize_queue();
err_init_queue:
  pthread_mutex_destroy(&lock);
err_mutex_init:
err_invalid_config:
  json_object_put(json_root);
err_invalid_json:
  return retval;
}
