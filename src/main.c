#define _GNU_SOURCE // Without this, VSCode keeps complaining that sigaction is
                    // an "incomplete type"

#include <arpa/inet.h>
#include <dirent.h> /* Check directory's existence*/
#include <errno.h>
#include <libgen.h> /* dirname() */
#include <linux/limits.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <json-c/json.h> /* JSON */
#include <microhttpd.h>

#include "queue.h"
#include "utils.h"

#define SSL_FILE_BUFF_SIZE 8192
const char *http_auth_username;
const char *http_auth_password;

volatile sig_atomic_t e_flag = 0;

static void signal_handler(int signum) {
  char msg[] = "Signal [  ] caught\n";
  msg[8] = '0' + (char)(signum / 10);
  msg[9] = '0' + (char)(signum % 10);
  write(STDIN_FILENO, msg, strlen(msg));
  e_flag = 1;
}

enum MHD_Result
resp_sound_name_not_supplied(struct MHD_Connection *connection) {

  char msg[PATH_MAX];
  snprintf(msg, PATH_MAX - 1, "Parameter sound_name not supplied");
  struct MHD_Response *resp = MHD_create_response_from_buffer(
      strlen(msg), (void *)msg, MHD_RESPMEM_MUST_COPY);
  enum MHD_Result ret =
      MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, resp);
  MHD_destroy_response(resp);
  return ret;
}

enum MHD_Result resp_invalid_sound_name(struct MHD_Connection *conn,
                                        const char *sound_name) {

  char msg[PATH_MAX];
  snprintf(msg, PATH_MAX - 1, "sound_name [%s] is invalid", sound_name);
  syslog(LOG_WARNING, "%s", msg);
  struct MHD_Response *resp = MHD_create_response_from_buffer(
      strlen(msg), (void *)msg, MHD_RESPMEM_MUST_COPY);
  enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_BAD_REQUEST, resp);
  MHD_destroy_response(resp);
  return ret;
}

enum MHD_Result resp_sound_inaccessible(struct MHD_Connection *conn,
                                        const char *sound_name) {

  char msg[PATH_MAX];
  snprintf(msg, PATH_MAX - 1, "sound_name [%s] is inaccessible", sound_name);
  syslog(LOG_WARNING, "%s", msg);
  struct MHD_Response *resp = MHD_create_response_from_buffer(
      strlen(msg), (void *)msg, MHD_RESPMEM_MUST_COPY);
  MHD_add_response_header(resp, "Content-Type", "text/html; charset=utf-8");
  enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_BAD_REQUEST, resp);
  MHD_destroy_response(resp);
  return ret;
}

enum MHD_Result resp_404(struct MHD_Connection *conn) {

  char msg[PATH_MAX];
  snprintf(msg, PATH_MAX - 1, "Resource not found");
  syslog(LOG_WARNING, "%s", msg);
  struct MHD_Response *resp = MHD_create_response_from_buffer(
      strlen(msg), (void *)msg, MHD_RESPMEM_MUST_COPY);
  enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_NOT_FOUND, resp);
  MHD_destroy_response(resp);
  return ret;
}

enum MHD_Result resp_add_sound_to_queue(struct MHD_Connection *conn,
                                        const char *sound_name,
                                        const char *sound_realpath) {
  enum MHD_Result ret;
  struct MHD_Response *resp = NULL;
  char msg[PATH_MAX];
  int r;
  ssize_t qs = get_queue_size();
  if (enqueue(sound_realpath) == 0) {
    if (qs == 0) { // i.e., before enqueue() the queue is empty, so we start
                   // a new handle_sound_name_queue thread.
      syslog(LOG_INFO, "sound_queue is currently empty, starting new thread to "
                       "handle the queue.");
      pthread_t my_thread;
      if (pthread_create(&my_thread, NULL, handle_sound_name_queue, NULL) !=
          0) {
        snprintf(msg, PATH_MAX - 1,
                 "Failed to pthread_create() handle_sound_name_queue: %d(%s)",
                 errno, strerror(errno));
        syslog(LOG_ERR, "%s", msg);
        resp = MHD_create_response_from_buffer(strlen(msg), (void *)msg,
                                               MHD_RESPMEM_MUST_COPY);
        ret = MHD_queue_response(conn, MHD_HTTP_BAD_REQUEST, resp);
        MHD_destroy_response(resp);
        return ret;
      } else if ((r = pthread_detach(my_thread)) != 0) {
        snprintf(msg, PATH_MAX - 1,
                 "handle_sound_name_queue pthread_create()'ed, but failed "
                 "to pthread_detach() it, reason: %d. This is not considered "
                 "an error but might lead to resource leakage",
                 r);
        syslog(LOG_WARNING, "%s", msg);
      }
    }

    snprintf(msg, PATH_MAX - 1,
             "[%s] added to sound_queue, sound_queue_size: %ld "
             "(MAX_SOUND_QUEUE_SIZE: %d)",
             sound_name, get_queue_size(), MAX_SOUND_QUEUE_SIZE);
    syslog(LOG_INFO, "%s", msg);
    resp = MHD_create_response_from_buffer(strlen(msg), (void *)msg,
                                           MHD_RESPMEM_MUST_COPY);
    MHD_add_response_header(resp, "Content-Type", "text/html; charset=utf-8");
    ret = MHD_queue_response(conn, MHD_HTTP_OK, resp);
    MHD_destroy_response(resp);
    return ret;
  }
  if (qs == MAX_SOUND_QUEUE_SIZE) {
    snprintf(msg, PATH_MAX - 1,
             "queue is full, new sound discarded. queue_size: %ld, "
             "MAX_SOUND_QUEUE_SIZE: %d",
             qs, MAX_SOUND_QUEUE_SIZE);
  } else {
    snprintf(msg, PATH_MAX - 1,
             "Server has not enough free memory, new sound discarded.");
  }
  syslog(LOG_ERR, "%s", msg);
  resp = MHD_create_response_from_buffer(strlen(msg), (void *)msg,
                                         MHD_RESPMEM_MUST_COPY);
  ret = MHD_queue_response(conn, MHD_HTTP_INTERNAL_SERVER_ERROR, resp);
  MHD_destroy_response(resp);
  return ret;
}

enum MHD_Result
request_handler(__attribute__((unused)) void *cls, struct MHD_Connection *conn,
                const char *url, const char *method,
                __attribute__((unused)) const char *version,
                __attribute__((unused)) const char *upload_data,
                __attribute__((unused)) size_t *upload_data_size, void **ptr) {
  static int aptr;
  // const char *me = (const char *)cls;
  struct MHD_Response *resp = NULL;
  enum MHD_Result ret;
  char *user;
  char *pass = NULL;
  int fail;

  if (0 != strcmp(method, MHD_HTTP_METHOD_GET))
    return MHD_NO; /* unexpected method */
  if (&aptr != *ptr) {
    /* do never respond on first call */
    *ptr = &aptr;
    return MHD_YES;
  }
  *ptr = NULL; /* reset when done */

  user = MHD_basic_auth_get_username_password(conn, &pass);
  fail = ((user == NULL) || (0 != strcmp(user, http_auth_username)) ||
          (0 != strcmp(pass, http_auth_password)));
  MHD_free(user);
  MHD_free(pass);

  if (fail) {
    const char msg[] = "Access denied";
    resp = MHD_create_response_from_buffer(strlen(msg), (void *)msg,
                                           MHD_RESPMEM_MUST_COPY);
    ret = MHD_queue_basic_auth_fail_response(conn, "PA Client Realm", resp);
    MHD_destroy_response(resp);
    return ret;
  }

  if (strcmp(url, "/health_check/") == 0) {
    const char msg[] = "Client is up and running";
    resp = MHD_create_response_from_buffer(strlen(msg), (void *)msg,
                                           MHD_RESPMEM_MUST_COPY);
    ret = MHD_queue_response(conn, MHD_HTTP_OK, resp);
    MHD_destroy_response(resp);
    return ret;
  }

  if (strcmp(url, "/") == 0) {
    // According to official querystring example:
    // https://github.com/pmq20/libmicrohttpd/blob/master/src/examples/querystring_example.c
    // return value from MHD_lookup_connection_value() should not be free()ed
    const char *sound_name =
        MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "sound_name");
    if (sound_name == NULL) {
      return resp_sound_name_not_supplied(conn);
    }

    if (strstr(sound_name, "/..") != NULL ||
        strstr(sound_name, "../") != NULL || strlen(sound_name) > 256) {
      return resp_invalid_sound_name(conn, sound_name);
    }

    char sound_path[PATH_MAX + 1] = "", sound_realpath[PATH_MAX + 1];
    strcat(sound_path, sound_repository_path);
    strcat(sound_path, sound_name);
    realpath(sound_path, sound_realpath);
    if (is_file_accessible(sound_realpath) == false) {
      return resp_sound_inaccessible(conn, sound_name);
    }
    return resp_add_sound_to_queue(conn, sound_name, sound_realpath);
  }

  return resp_404(conn);
}

int load_ssl_key_or_crt(const char *path, char **out_content) {
  FILE *fp;
  int retval = 0;
  fp = fopen(path, "rb");
  if (fp == NULL) {
    syslog(LOG_ERR, "Failed to fopen() %s", path);
    retval = -1;
    goto err_fopen;
  }

  size_t bytes_read = fread(out_content, sizeof(char), SSL_FILE_BUFF_SIZE, fp);
  if (bytes_read > 0) {
  } else if (feof(fp)) {
    syslog(LOG_ERR, "feof() error while reading from [%s]", path);
  } else if (ferror(fp)) {
    syslog(LOG_ERR, "ferror() while` reading from [%s]", path);
    retval = -1;
    goto err_ferror;
  }
err_ferror:
  fclose(fp);
err_fopen:
  return retval;
}

struct MHD_Daemon *init_mhd(const char *interface, const int port,
                            const char *ssl_crt, const char *ssl_key) {

  struct sockaddr_in server_addr;
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(port);
  if (inet_pton(AF_INET, interface, &(server_addr.sin_addr)) < 0) {
    syslog(LOG_ERR, "inet_pton() error: %d(%s)", errno, strerror(errno));
    return NULL;
  }

  struct MHD_Daemon *daemon;
  // clang-format off
  daemon = MHD_start_daemon(
                       MHD_USE_INTERNAL_POLLING_THREAD | MHD_USE_DEBUG | MHD_USE_TLS,
                       port, NULL,
                       NULL, &request_handler, "",
                       MHD_OPTION_CONNECTION_TIMEOUT, 256,
                       MHD_OPTION_SOCK_ADDR, (struct sockaddr *)&server_addr,
                       MHD_OPTION_HTTPS_MEM_CERT, ssl_crt,
                       MHD_OPTION_HTTPS_MEM_KEY, ssl_key,
                       MHD_OPTION_END);
  // clang-format on
  if (daemon == NULL) {
    syslog(LOG_ERR, "MHD_start_daemon() failed");
    return NULL;
  }
  syslog(LOG_INFO, "HTTP server listening on https://%s:%d", interface, port);
  return daemon;
}

int check_sound_repo_validity(const char *sound_repository_path) {
  if (sound_repository_path == NULL ||
      strnlen(sound_repository_path, PATH_MAX) >= PATH_MAX / 2) {
    syslog(LOG_ERR, "sound_repository [%s] is either NULL or too long",
           sound_repository_path);
    return -1;
  }
  DIR *dir = opendir(sound_repository_path);
  if (dir) { // exist
    closedir(dir);
  } else {
    syslog(LOG_ERR, "sound_repository [%s] is inaccessible.",
           sound_repository_path);
    return -2;
  }
  return 0;
}

int load_values_from_json(const char *argv0, json_object **json_root_out,
                          const char **out_interface, int *out_port,
                          char **out_ssl_crt, char **out_ssl_key) {
  char bin_path[PATH_MAX], settings_path[PATH_MAX] = "";
  if (realpath(argv0, bin_path) == NULL) {
    syslog(LOG_ERR, "realpath() failed: %d(%s)", errno, strerror(errno));
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
    syslog(LOG_ERR, "Some required values are not provided");
    return -3;
  }
  if (load_ssl_key_or_crt(ssl_crt_path, out_ssl_crt) < 0) {
    syslog(LOG_ERR, "Failed to read SSL certificate file");
    return -4;
  }
  if (load_ssl_key_or_crt(ssl_key_path, out_ssl_key) < 0) {
    syslog(LOG_ERR, "Failed to read SSL key file");
    return -4;
  }
  *out_interface = json_object_get_string(root_app_interface);
  *out_port = atoi(json_object_get_string(root_app_port));
  *json_root_out = root;
  return 0;
}

int install_signal_handler() {
  // This design canNOT handle more than 99 signal types
  if (_NSIG > 99) {
    syslog(LOG_ERR, "signal_handler() can't handle more than 99 signals");
    return -1;
  }
  struct sigaction act;
  // Initialize the signal set to empty, similar to memset(0)
  if (sigemptyset(&act.sa_mask) == -1) {
    syslog(LOG_ERR, "sigemptyset()");
    return -2;
  }
  act.sa_handler = signal_handler;
  /* SA_RESETHAND means we want our signal_handler() to intercept the signal
  once. If a signal is sent twice, the default signal handler will be used
  again. `man sigaction` describes more possible sa_flags. */
  act.sa_flags = SA_RESETHAND;
  // act.sa_flags = 0;
  if (sigaction(SIGINT, &act, 0) == -1 || sigaction(SIGTERM, &act, 0) == -1) {
    syslog(LOG_ERR, "sigaction()");
    return -3;
  }
  return 0;
}

int main(__attribute__((unused)) int argc, char **argv) {
  int retval = 0;
  const char *interface; // Lifecycle is managed by json_object, don't free()
  int port;
  char ssl_key[SSL_FILE_BUFF_SIZE], ssl_crt[SSL_FILE_BUFF_SIZE];
  json_object *json_root;

  (void)openlog(argv[0], LOG_PID | LOG_CONS, 0);

  if (install_signal_handler() < 0) {
    retval = -1;
    goto err_install_sighandler;
  }

  if (load_values_from_json(argv[0], &json_root, &interface, &port,
                            (char **)(&ssl_crt), (char **)(&ssl_key)) < 0) {
    retval = -1;
    if (json_root == NULL) {
      goto err_invalid_json;
    }
    goto err_invalid_config;
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
  syslog(LOG_INFO, "initialized");

  // getc() won't work without an interactive shell.
  // (void)getc(stdin);
  while (e_flag == 0) {
    sleep(1);
  }
  syslog(LOG_INFO, "exiting");
  MHD_stop_daemon(d);
err_init_mhd:
  finalize_queue();
err_init_queue:
err_invalid_config:
  json_object_put(json_root);
err_invalid_json:
err_install_sighandler:
  closelog();
  return retval;
}
