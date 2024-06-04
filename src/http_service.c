#include "http_service.h"
#include "queue.h"
#include "utils.h"

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <syslog.h>

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
  ssize_t qs = pacq_get_queue_size();
  if (pacq_enqueue(sound_realpath) == 0) {
    if (qs == 0) { // i.e., before pacq_enqueue() the queue is empty, so we
                   // start a new handle_sound_name_queue thread.
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
             "[%s] added to sound_queue, sound_queue_size: %zd "
             "(MAX_SOUND_QUEUE_SIZE: %d)",
             sound_name, pacq_get_queue_size(), MAX_SOUND_QUEUE_SIZE);
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
             "queue is full, new sound discarded. queue_size: %zd, "
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
    // return value from MHD_lookup_connection_value() should not be free()'ed
    const char *sound_name =
        MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "sound_name");
    if (sound_name == NULL) {
      return resp_sound_name_not_supplied(conn);
    }
    const char *delay_ms_char =
        MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "delay_ms");
    int delay_ms = 0;
    if (delay_ms_char != NULL && strlen(delay_ms_char) < 8) {
      delay_ms = abs(atoi(delay_ms_char));
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
    usleep(delay_ms * 1000);
    return resp_add_sound_to_queue(conn, sound_name, sound_realpath);
  }

  return resp_404(conn);
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
