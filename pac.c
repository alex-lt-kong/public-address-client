#include <onion/onion.h>
#include <onion/log.h>
#include <onion/version.h>
#include <onion/shortcuts.h>
#include <signal.h>
#include <limits.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/wait.h> /* for waitpid */
#include <pthread.h>

#include "queue.c"

const char* sound_repository_path;
pthread_mutex_t lock;

void* handle_sound_name_queue() {
    start_label:;
    list_queue_items();
    char* sound_name = peek();
    if (sound_name == NULL) {
        fprintf(stderr, "queue is already empty/memory allocation failed\n");
    }
    if (strnlen(sound_name, NAME_MAX) >= NAME_MAX) {
        fprintf(stderr, "sound_name too long\n");
    }
    char sound_path[PATH_MAX] = "", sound_realpath[PATH_MAX];
    strcat(sound_path, sound_repository_path);
    strcat(sound_path, sound_name);
    free(sound_name);
    realpath(sound_path, sound_realpath);
    if (sound_realpath == NULL) {
        fprintf(stderr, "sound_realpath == NULL\n");
    }
    
    // https://stackoverflow.com/questions/5460421/how-do-you-write-a-c-program-to-execute-another-program
    pid_t pid = fork();
    if (pid == 0) { /* child process */
        //char* argv[]={"mpg123", "-o", "alsa:hw:1,0", sound_realpath, NULL};
        char* argv[]={"mpg123", sound_realpath, NULL};
        execv("/usr/bin/mpg123",argv); // this call only returns if an error occurs!
        exit(1);
    } else { /* pid!=0; parent process */
        waitpid(pid, 0, 0); /* wait for child to exit */
        pthread_mutex_lock(&lock);
        dequeue();        
        if (get_queue_size() > 0) {
            pthread_mutex_unlock(&lock);
            goto start_label;
        }
        pthread_mutex_unlock(&lock);
    }
}

int health_check(void *p, onion_request *req, onion_response *res) {
    return onion_shortcut_response("Client is up and running.\n", HTTP_OK, req, res);
}

int index_page(void *p, onion_request *req, onion_response *res) {
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
                return onion_shortcut_response(
                    "sound_name invalid (NULL or too long)", HTTP_BAD_REQUEST, req, res
                );
            }
            strcat(custom_sound_name, "custom-event/");
            strcat(custom_sound_name, sound_name);
        }
        pthread_mutex_lock(&lock);
        if (enqueue(custom_sound_name)) {
            list_queue_items();
            int qs = get_queue_size();
            pthread_mutex_unlock(&lock);
            if (get_queue_size() == 1) {                
                pthread_t my_thread;
                pthread_create(&my_thread, NULL, handle_sound_name_queue, NULL); // no parentheses here 
            }
            onion_response_printf(
                res, "OK, sound [%s] added to sound_queue, notification_type == [%s]", custom_sound_name, notification_type
            );
            return OCS_PROCESSED;
        } else {
            pthread_mutex_unlock(&lock);
            return onion_shortcut_response(
                "queue is full/server has not enough free memory, new sound discarded.\n", HTTP_BAD_REQUEST, req, res
            );
        }
    }
    onion_response_printf(res, "notification_type's value [%s] is invalid\n", notification_type);
	return OCS_PROCESSED;
}


onion *o=NULL;

static void shutdown_server(int _){
	if (o)
		onion_listen_stop(o);
}


int main(int argc, char **argv){
    if (argc != 3) {
        fprintf(stderr, "usage: [sound_repository] [port]");
        return 1;
    } else if (strnlen(argv[1], PATH_MAX) >= PATH_MAX / 2) {
        fprintf(stderr, "sound_repository too long");
        return 2;
    }
    
    sound_repository_path = argv[1];
    if (pthread_mutex_init(&lock, NULL) != 0) {
        fprintf(stderr, "mutex init failed\n.");
        return 3;
    }

	signal(SIGINT,shutdown_server);
	signal(SIGTERM,shutdown_server);

	ONION_VERSION_IS_COMPATIBLE_OR_ABORT();
    
    initialize_queue();
    o=onion_new(O_THREADED);
    onion_set_timeout(o, 5000);
    onion_set_hostname(o,"0.0.0.0");
    onion_set_port(o, argv[2]); 	
    onion_url *urls=onion_root_url(o);
    onion_url_add(urls, "", index_page);
    onion_url_add(urls, "health_check/", health_check);
    

	onion_listen(o);
	onion_free(o);
    finalize_queue();
    pthread_mutex_destroy(&lock);
	return 0;
}
