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

void* handle_sound_name_queue() {
    start_label:;
    list_queue_items();
    char* sound_name = peek();
    if (sound_name == NULL) {
        fprintf(stderr, "queue is already empty\n");
    }
    if (strnlen(sound_name, PATH_MAX) >= PATH_MAX / 2) {
        fprintf(stderr, "sound_name too long\n");
    }
    char sound_path[PATH_MAX], sound_realpath[PATH_MAX];
    strcpy(sound_path, sound_repository_path);
    strcat(sound_path, sound_name);
    realpath(sound_path, sound_realpath);
    if (sound_realpath == NULL) {
        fprintf(stderr, "sound_realpath == NULL\n");
    }
    printf("in play_sound(), sound_name is %s; sound_realpath is %s\n", sound_name, sound_realpath);
    
    // https://stackoverflow.com/questions/5460421/how-do-you-write-a-c-program-to-execute-another-program
    pid_t pid = fork();
    if (pid == 0) { /* child process */
        char* argv[]={"mpg123", "-o", "alsa:hw:1,0", sound_realpath, NULL};
        execv("/usr/bin/mpg123",argv); // this call only returns if an error occurs!
     //   return 4;
    }
    else { /* pid!=0; parent process */
        waitpid(pid, 0, 0); /* wait for child to exit */
        dequeue();
        free(sound_name);
        if (get_queue_size() > 0) {
            goto start_label;
        }
    }
}

int index_page(void *p, onion_request *req, onion_response *res){
	const char* notification_type = onion_request_get_query(req, "notification_type");
    const char* sound_name = onion_request_get_query(req, "sound_name");
    if (notification_type == NULL) {
        return onion_shortcut_response("Parameter notification_type is missing", HTTP_BAD_REQUEST, req, res);
    }
    if (strcmp(notification_type, "custom") == 0) {
        if (sound_name == NULL || strnlen(sound_name, NAME_MAX) > NAME_MAX) {
            return onion_shortcut_response(
                "sound_name invalid (NULL or too long)", HTTP_BAD_REQUEST, req, res
            );    
        }
        char custom_sound_name[NAME_MAX + 32] = "custom-event/";
        strcat(custom_sound_name, sound_name);
        if (enqueue(custom_sound_name)) {
            list_queue_items();
        } else {
            fprintf(stderr, "queue is full, new sound discarded.\n");
        }
        if (get_queue_size() == 1) {
            pthread_t my_thread;
            pthread_create(&my_thread, NULL, handle_sound_name_queue, NULL); // no parentheses here 
        }
        return onion_shortcut_response(
            "OK, pushed to sound_stack, notification_type == custom", HTTP_OK, req, res
        );
    } 
    else if (strcmp(notification_type, "chiming") == 0) {
        if (enqueue("cuckoo-clock-sound-0727.mp3")) {
            list_queue_items();
        } else {
            fprintf(stderr, "queue is full, new sound discarded.\n");
        }
        if (get_queue_size() == 1) {
            pthread_t my_thread;
            pthread_create(&my_thread, NULL, handle_sound_name_queue, NULL); // no parentheses here 
        }
        return onion_shortcut_response("OK! (notification_type == chiming)", HTTP_OK, req, res);
    }
    else {
        return onion_shortcut_response("notification_type's value is invalid", HTTP_BAD_REQUEST, req, res);
    }
	return OCS_PROCESSED;
}


onion *o=NULL;

static void shutdown_server(int _){
	if (o)
		onion_listen_stop(o);
}


int main(int argc, char **argv){
    if (argc != 2) {
        fprintf(stderr, "sound_repository not specified");
        return 1;
    } else if (strnlen(argv[1], PATH_MAX) >= PATH_MAX / 2) {
        fprintf(stderr, "sound_repository too long");
        return 2;
    }
    
    sound_repository_path = argv[1];
    

	signal(SIGINT,shutdown_server);
	signal(SIGTERM,shutdown_server);

	ONION_VERSION_IS_COMPATIBLE_OR_ABORT();
    initialize_queue();
	o=onion_new(O_POOL);
	onion_set_timeout(o, 5000);
	onion_set_hostname(o,"0.0.0.0");
	onion_set_port(o, "9527"); 	
	onion_url *urls=onion_root_url(o);

	onion_url_add(urls, "", index_page);

	onion_listen(o);
	onion_free(o);
	return 0;
}
