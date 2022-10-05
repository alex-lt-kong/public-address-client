#include <onion/onion.h>
#include <onion/version.h>
#include <onion/shortcuts.h>
#include <errno.h>
#include <signal.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/wait.h> /* for waitpid */
/* JSON */
#include <json-c/json.h>
/* Check directory's existence*/
#include <dirent.h>
#include <libgen.h> /* dirname() */

#include "utils.h"
#include "queue.h"

int health_check(void *p, onion_request *req, onion_response *res) {
    return onion_shortcut_response("Client is up and running.\n", HTTP_OK, req, res);
}

int index_page(void *p, onion_request *req, onion_response *res) {

  char err_msg[PATH_MAX];
  char info_msg[PATH_MAX];
  if (authenticate(req, res) == false) {
    ONION_WARNING("Failed login attempt");
    return OCS_PROCESSED;
  }

  const char* sound_name = onion_request_get_query(req, "sound_name");
  if (sound_name == NULL || strnlen(sound_name, NAME_MAX) >= NAME_MAX) {
    snprintf(err_msg, PATH_MAX, "sound_name invalid (NULL or too long)");
    ONION_WARNING(err_msg);
    return onion_shortcut_response(err_msg, HTTP_BAD_REQUEST, req, res);
  }
  if (strstr(sound_name,"/..") != NULL || strstr(sound_name,"../") != NULL) {
    snprintf(err_msg, PATH_MAX, "sound_name [%s] may try to escape from sound_repository_path", sound_name);
    ONION_WARNING(err_msg);
		return onion_shortcut_response(err_msg, HTTP_BAD_REQUEST, req, res);
	}

  char sound_path[PATH_MAX] = "", sound_realpath[PATH_MAX];
  strcat(sound_path, sound_repository_path);
  strcat(sound_path, sound_name);
  realpath(sound_path, sound_realpath);
  if (is_file_accessible(sound_realpath) == false) {
    snprintf(err_msg, PATH_MAX, "sound_name [%s] is inaccessible", sound_name);
    ONION_WARNING(err_msg);
		return onion_shortcut_response(err_msg, HTTP_BAD_REQUEST, req, res);
  }

  pthread_mutex_lock(&lock);
  int qs = get_queue_size();
  if (enqueue(sound_realpath)) {
    pthread_mutex_unlock(&lock);
    if (qs == 0) { // i.e., before enqueue() the queue is empty, so we start a new handle_sound_name_queue thread.
      pthread_t my_thread;
      if (pthread_create(&my_thread, NULL, handle_sound_name_queue, NULL) != 0) {
        ONION_ERROR("Failed to pthread_create() handle_sound_name_queue, reason: %s", strerror(errno));
      } else {
        if (pthread_detach(my_thread) == 0) {
          // We need to detach the thread so when handle_sound_name_queue() returns, the thread resources will be
          // fully released; otherwise, it is suspected that some thread resources will NOT be released and we will
          // be unable to pthread_create() new thread a while later, resulting in "Cannot allocate memory" error.
          ONION_INFO("handle_sound_name_queue pthread_create()'ed");
        } else {
          ONION_ERROR(
            "handle_sound_name_queue pthread_create()'ed, but failed to pthread_detach() it, reason: %s",
            my_thread, strerror(errno)
          );
        }
      }
    }
    snprintf(info_msg, PATH_MAX, "[%s] added to sound_queue, sound_queue_size: %d", sound_name, qs+1);      
    ONION_INFO(info_msg);
    return onion_shortcut_response(info_msg, HTTP_OK, req, res);
  } else {
    pthread_mutex_unlock(&lock);
    snprintf(err_msg, PATH_MAX, "queue is full/server has not enough free memory, new sound discarded.");
    ONION_WARNING(err_msg);
    return onion_shortcut_response(err_msg, HTTP_BAD_REQUEST, req, res);
  }
}


onion *o=NULL;

static void shutdown_server(int _){
	if (o)
		onion_listen_stop(o);
}


int main(int argc, char **argv) {

  char bin_path[PATH_MAX], settings_path[PATH_MAX] = "";
  realpath(argv[0], bin_path);
  strcpy(settings_path, dirname(bin_path));
  strcat(settings_path, "/settings.json");
  json_object* root = json_object_from_file(settings_path);
  json_object* root_app = json_object_object_get(root, "app");
  json_object* root_app_port = json_object_object_get(root_app, "port");
  json_object* root_app_interface = json_object_object_get(root_app, "interface");
  json_object* root_app_sound_repo_path = json_object_object_get(root_app, "sound_repo_path");
  json_object* root_app_username = json_object_object_get(root_app, "username");
  json_object* root_app_passwd = json_object_object_get(root_app, "passwd");
  json_object* root_app_ssl = json_object_object_get(root_app, "ssl");
  json_object* root_app_ssl_crt_path = json_object_object_get(root_app_ssl, "crt_path");
  json_object* root_app_ssl_key_path = json_object_object_get(root_app_ssl, "key_path");
  json_object* root_app_log_path = json_object_object_get(root_app, "log_path");
  
  sound_repository_path = json_object_get_string(root_app_sound_repo_path);
  pac_username = json_object_get_string(root_app_username);
  pac_passwd = json_object_get_string(root_app_passwd);
  const char* log_path = json_object_get_string(root_app_log_path);
  const char* ssl_crt_path = json_object_get_string(root_app_ssl_crt_path);
  const char* ssl_key_path = json_object_get_string(root_app_ssl_key_path);

  if (sound_repository_path == NULL || strnlen(sound_repository_path, PATH_MAX) >= PATH_MAX / 2) {
    ONION_ERROR("sound_repository [%s] is either NULL or too long", sound_repository_path);
    return 2;
  }
  if (
    log_path ==NULL || pac_username == NULL || pac_passwd == NULL ||
    ssl_crt_path == NULL || ssl_key_path == NULL
  ) {
    ONION_ERROR("Either root_app_log_path, username, passwd, ssl_crt_path, ssl_key_path is not set.");
    return 3;
  }
  DIR* dir = opendir(sound_repository_path);
  if (dir) { // exist
    closedir(dir);
  } else {
    ONION_ERROR("sound_repository [%s] is inaccessible.", sound_repository_path);
    return 4;
  }
  if (pthread_mutex_init(&lock, NULL) != 0) {
      ONION_ERROR("Failed to initialize a mutex");
      return 5;
  }
  if (argc == 2 && strcmp(argv[1], "--debug") == 0) {
    fprintf(stderr, "Debug mode enabled, the only change is that log will be sent to stderr instead of a log file\n");
  } else {
    freopen(log_path, "a", stderr);
  }

  signal(SIGINT,shutdown_server);
  signal(SIGTERM,shutdown_server);

  ONION_VERSION_IS_COMPATIBLE_OR_ABORT();
  
  initialize_queue();
  o=onion_new(O_THREADED);
  onion_set_timeout(o, 300 * 1000);
  // We set this to a large number, hoping the client closes the connection itself
  // If the server times out before client does, GnuTLS complains "The TLS connection was non-properly terminated."
  onion_set_certificate(o, O_SSL_CERTIFICATE_KEY, ssl_crt_path, ssl_key_path);
  onion_set_hostname(o, json_object_get_string(root_app_interface));
  onion_set_port(o, json_object_get_string(root_app_port));
  onion_url *urls=onion_root_url(o);
  onion_url_add(urls, "", index_page);
  onion_url_add(urls, "health_check/", health_check);
  
  ONION_INFO(
    "Public address client listening on %s:%s",
    json_object_get_string(root_app_interface), json_object_get_string(root_app_port)
  );
  onion_listen(o);
  onion_free(o);
  finalize_queue();
  json_object_put(root);
  pthread_mutex_destroy(&lock);
  freopen("/dev/tty", "a", stderr); // may have side effects, but fit our purpose for the time being.
  return 0;
}
