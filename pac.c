#include <onion/onion.h>
#include <onion/log.h>
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
#include <pthread.h>
/* play MP3 files */
#include <ao/ao.h>
#include <mpg123.h>
/* JSON */
#include <json-c/json.h>
/* Check directory's existence*/
#include <dirent.h>


#include "queue.h"

const char* sound_repository_path;
pthread_mutex_t lock;

int play_sound(const char* sound_path) {
    // This function an its variants seems everywhere on the Internet, my version
    // comes from: https://hzqtc.github.io/2012/05/play-mp3-with-libmpg123-and-libao.html
    mpg123_handle *mh;
    unsigned char *buffer;
    size_t buffer_size;
    size_t done;
    int err;

    int driver;
    ao_device *dev;

    ao_sample_format format;
    int channels, encoding;
    long rate;

    /* initializations */
    ao_initialize();
    driver = ao_default_driver_id();
    mpg123_init();
    mh = mpg123_new(NULL, &err);
    buffer_size = mpg123_outblock(mh);
    buffer = (unsigned char*) malloc(buffer_size * sizeof(unsigned char));

    /* open the file and get the decoding format */
    mpg123_open(mh, sound_path);
    mpg123_getformat(mh, &rate, &channels, &encoding);

    /* set the output format and open the output device */
    format.bits = mpg123_encsize(encoding) * 8; // bytes * 8 to bits
    format.rate = rate;
    format.channels = channels;
    format.byte_format = AO_FMT_NATIVE;
    format.matrix = 0;
    dev = ao_open_live(driver, &format, NULL);

    /* decode and play */
    while (mpg123_read(mh, buffer, buffer_size, &done) == MPG123_OK)
        ao_play(dev, buffer, done);

    /* clean up */
    free(buffer);
    ao_close(dev);
    mpg123_close(mh);
    mpg123_delete(mh);
    mpg123_exit();
    ao_shutdown();

    return 0;
}

void* handle_sound_name_queue() {
    while (1) {
        char* queue_str = list_queue_items();
        printf("%s", queue_str);
        free(queue_str);
        size_t qs = get_queue_size();
        pthread_mutex_unlock(&lock);
        if (qs == 0) {
            onion_log_stderr(O_INFO, "pac.c", 25, "sound_name_queue cleared, thread quited\n");
            break;
        }

        char* sound_name = peek();
        if (sound_name == NULL) {
            onion_log_stderr(
                O_ERROR, "pac.c", 25,
                "Failed to peek() a non-empty queue. The 1st item will be directly dequeue()'ed\n", sound_name
            );
            pthread_mutex_lock(&lock);
            dequeue();
            continue;
        }
        if (strnlen(sound_name, NAME_MAX) >= NAME_MAX) {
            onion_log_stderr(
                O_ERROR, "pac.c", 25,
                "sound_name [%s] too long. The 1st item  will be directly dequeue()'ed\n", sound_name
            );
            pthread_mutex_lock(&lock);
            dequeue();
            continue;
        }

        char sound_path[PATH_MAX] = "", sound_realpath[PATH_MAX];
        strcat(sound_path, sound_repository_path);
        strcat(sound_path, sound_name);
        free(sound_name);
        realpath(sound_path, sound_realpath);
        if (sound_realpath == NULL) {
            onion_log_stderr(O_ERROR, "pac.c", 48, "sound_realpath == NULL. It will be directly dequeue()'ed\n");
        }
        play_sound(sound_realpath);
        pthread_mutex_lock(&lock);
        dequeue();
    }
}

int health_check(void *p, onion_request *req, onion_response *res) {
    return onion_shortcut_response("Client is up and running.\n", HTTP_OK, req, res);
}

int index_page(void *p, onion_request *req, onion_response *res) {
    char err_msg[PATH_MAX];
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
            char* queue_str = list_queue_items();
            printf("%s", queue_str);
            free(queue_str);     
            pthread_mutex_unlock(&lock);
            if (qs == 0) { // i.e., before enqueue() the queue is empty, so we start a new handle_sound_name_queue thread.
                pthread_t my_thread;
                pthread_create(&my_thread, NULL, handle_sound_name_queue, NULL); // no parentheses here 
            }
            onion_response_printf(
                res, "OK, sound [%s] added to sound_queue, notification_type == [%s]", custom_sound_name, notification_type
            );
            return OCS_PROCESSED;
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
    sound_repository_path = json_object_get_string(root_app_sound_repo_path);
    if (sound_repository_path == NULL || strnlen(sound_repository_path, PATH_MAX) >= PATH_MAX / 2) {
        onion_log_stderr(
            O_ERROR, "pac.c", 195, "sound_repository [%s] is either NULL or too long\n", sound_repository_path
        );
        return 2;
    }
    DIR* dir = opendir("mydir");
    if (dir) { // exist
        closedir(dir);
    } else {
        onion_log_stderr(
            O_ERROR, "pac.c", 205,
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
