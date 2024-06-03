#define _GNU_SOURCE // Without this, VSCode keeps complaining that sigaction is
                    // an "incomplete type"

#include "http_service.h"
#include "queue.h"
#include "utils.h"

#include <json-c/json.h> /* JSON */
#include <microhttpd.h>

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

#define SSL_FILE_BUFF_SIZE 8192

volatile sig_atomic_t e_flag = 0;

static void signal_handler(int signum) {
  char msg[] = "Signal [  ] caught\n";
  msg[8] = '0' + (char)(signum / 10);
  msg[9] = '0' + (char)(signum % 10);
  write(STDIN_FILENO, msg, strlen(msg));
  e_flag = 1;
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
      syslog(LOG_ERR, "Failed to parse JSON file");
      goto err_invalid_json;
    }
    syslog(LOG_ERR, "Invalid configuration");
    goto err_invalid_config;
  }

  if (pacq_initialize_queue() < 0) {
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
  pacq_finalize_queue();
err_init_queue:
err_invalid_config:
  json_object_put(json_root);
err_invalid_json:
err_install_sighandler:
  closelog();
  return retval;
}
