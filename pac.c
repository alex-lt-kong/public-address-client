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

#include "utils.h"
#include "queue.h"

int health_check(void *p, onion_request *req, onion_response *res) {
    return onion_shortcut_response("Client is up and running.\n", HTTP_OK, req, res);
}

int index_page(void *p, onion_request *req, onion_response *res) {

  char err_msg[PATH_MAX];
  char info_msg[PATH_MAX];
  if (authenticate(req, res) == false) {
    snprintf(err_msg, PATH_MAX, "Failed login attempt");
    onion_log_stderr(O_WARNING, "pac.c", 30, err_msg);
    return OCS_PROCESSED;
  }

  const char* notification_type = onion_request_get_query(req, "notification_type");
  const char* sound_name = onion_request_get_query(req, "sound_name");
  if (notification_type == NULL) {
    return onion_shortcut_response("Parameter notification_type is missing", HTTP_BAD_REQUEST, req, res);
  }
  if (strcmp(notification_type, "custom") == 0 || strcmp(notification_type, "chiming") == 0) {
    char custom_sound_name[NAME_MAX + 32] = "";
    if (strcmp(notification_type, "chiming") == 0) {
      strcat(custom_sound_name, "cuckoo-clock-sound-0727.mp3");
    } else {
        if (sound_name == NULL || strnlen(sound_name, NAME_MAX) > NAME_MAX) {
            snprintf(err_msg, PATH_MAX, "sound_name invalid (NULL or too long)\n");
            onion_log_stderr(O_WARNING, "pac.c", 137, err_msg);
            return onion_shortcut_response(err_msg, HTTP_BAD_REQUEST, req, res);
        }
        strcat(custom_sound_name, "custom-event/");
        strcat(custom_sound_name, sound_name);
    }
    pthread_mutex_lock(&lock);
    int qs = get_queue_size();
    if (enqueue(custom_sound_name)) {
      pthread_mutex_unlock(&lock);
      if (qs == 0) { // i.e., before enqueue() the queue is empty, so we start a new handle_sound_name_queue thread.
        pthread_t my_thread;
        pthread_create(&my_thread, NULL, handle_sound_name_queue, NULL); // no parentheses here 
      }
      snprintf(
        info_msg, PATH_MAX, "[%s] added to sound_queue, notification_type == [%s], sound_queue_size: %d",
        custom_sound_name, notification_type, qs+1
      );
      onion_log_stderr(O_INFO, "pac.c", 160, info_msg);
      return onion_shortcut_response(info_msg, HTTP_OK, req, res);
    } else {
      pthread_mutex_unlock(&lock);
      snprintf(err_msg, PATH_MAX, "queue is full/server has not enough free memory, new sound discarded.\n");
      onion_log_stderr(O_WARNING, "pac.c", 160, err_msg);
      return onion_shortcut_response(err_msg, HTTP_BAD_REQUEST, req, res);
    }
  }
  snprintf(err_msg, PATH_MAX, "<meta charset=\"utf-8\">notification_type's value [%s] is invalid",notification_type);
  onion_log_stderr(O_WARNING, "pac.c", 165, err_msg);
  return onion_shortcut_response(err_msg, HTTP_BAD_REQUEST, req, res);
}


onion *o=NULL;

static void shutdown_server(int _){
	if (o)
		onion_listen_stop(o);
}


int main(int argc, char **argv){
    
    if (pthread_mutex_init(&lock, NULL) != 0) {
        onion_log_stderr(O_ERROR, "pac.c", 190, "Failed to initialize a mutex\n");
        return 1;
    }
    json_object* root = json_object_from_file("settings.json");
    json_object* root_app = json_object_object_get(root, "app");
    json_object* root_app_port = json_object_object_get(root_app, "port");
    json_object* root_app_interface = json_object_object_get(root_app, "interface");
    json_object* root_app_sound_repo_path = json_object_object_get(root_app, "sound_repo_path");
    json_object* root_app_username = json_object_object_get(root_app, "username");
    json_object* root_app_passwd = json_object_object_get(root_app, "passwd");
    sound_repository_path = json_object_get_string(root_app_sound_repo_path);
    pac_username = json_object_get_string(root_app_username);
    pac_passwd = json_object_get_string(root_app_passwd);
    if (sound_repository_path == NULL || strnlen(sound_repository_path, PATH_MAX) >= PATH_MAX / 2) {
      onion_log_stderr(
        O_ERROR, "pac.c", 100, "sound_repository [%s] is either NULL or too long\n", sound_repository_path
      );
      return 2;
    }
    if (pac_username == NULL || pac_passwd == NULL) {
      onion_log_stderr(O_ERROR, "pac.c", 110, "Either username or passwd is not set\n");
      return 3;
    }
    DIR* dir = opendir(sound_repository_path);
    if (dir) { // exist
      closedir(dir);
    } else {
      onion_log_stderr(
        O_ERROR, "pac.c", 100,
        "sound_repository [%s] either doesn't exist or is inaccessible\n", sound_repository_path
      );
      return 3;
    }

    signal(SIGINT,shutdown_server);
    signal(SIGTERM,shutdown_server);

    ONION_VERSION_IS_COMPATIBLE_OR_ABORT();
    
    initialize_queue();
    o=onion_new(O_THREADED);
    onion_set_hostname(o, json_object_get_string(root_app_interface));
    onion_set_port(o, json_object_get_string(root_app_port));
    onion_url *urls=onion_root_url(o);
    onion_url_add(urls, "", index_page);
    onion_url_add(urls, "health_check/", health_check);
    
    onion_log_stderr(
        O_INFO, "pac.c", 205, "Public address client listening on %s:%s",
        json_object_get_string(root_app_interface), json_object_get_string(root_app_port)
    );
    onion_listen(o);
    onion_free(o);
    finalize_queue();
    json_object_put(root);
    pthread_mutex_destroy(&lock);
    return 0;
}
