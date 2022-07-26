/** Licensed under AGPL 3.0. (C) 2010 David Moreno Montero. http://coralbits.com */
#include <onion/onion.h>
#include <onion/log.h>
#include <onion/version.h>
#include <onion/shortcuts.h>
#include <signal.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/wait.h> /* for waitpid */

int hello(void *p, onion_request *req, onion_response *res){
	//onion_response_set_length(res, 11);
	onion_response_write0(res,"Hello world");
	if (onion_request_get_query(req, "1")){
		onion_response_printf(res, "<p>Path: %s", onion_request_get_query(req, "1"));
	}
	onion_response_printf(res,"<p>Client description: %s",onion_request_get_client_description(req));
	return OCS_PROCESSED;
}
int play_sound(char* sound_name) {
    if (strnlen(sound_name, 1024) > 512 + 256) {
        return -1;
    }
    char sound_path[1024] = "../";
    strcat(sound_path, sound_name);
    printf("sound_path is %s\n", sound_path);
    // https://stackoverflow.com/questions/5460421/how-do-you-write-a-c-program-to-execute-another-program
    /*Spawn a child to run the program.*/
    pid_t pid = fork();
    if (pid == 0) { /* child process */
        printf("pid == 0!\n");
        static char *argv[]={"echo","Foo is my name.",NULL};
        execv("/bin/echo",argv);
        return 127;
    }
    else { /* pid!=0; parent process */
        printf("pid != 0!\n");
        waitpid(pid, 0, 0); /* wait for child to exit */
    }
}

int index_page(void *p, onion_request *req, onion_response *res){

	char* notification_type = onion_request_get_query(req, "notification_type");
    const char* sn = "sound_name";
    char* sound_name = onion_request_get_query(req, sn);
    if (notification_type == NULL) {
        return onion_shortcut_response("Parameter notification_type is missing", HTTP_BAD_REQUEST, req, res);
    }
    if (strcmp(notification_type, "custom") == 0) {
        if (sound_name == NULL || strnlen(sound_name, 1024) > 512) {
            return onion_shortcut_response(
                "sound_name invalid (NULL or too long)", HTTP_BAD_REQUEST, req, res
            );    
        }
        char sound_name_path[1024] = "sound-repository/";
        strcat(sound_name_path, sound_name);
        play_sound(sound_name_path);
        return onion_shortcut_response("notification_type == custom", HTTP_OK, req, res);
    } 
    else if (strcmp(notification_type, "chiming") == 0) {
        play_sound("cuckoo-clock-sound-0727.mp3");
        return onion_shortcut_response("notification_type == chiming", HTTP_OK, req, res);
    }
    else {
        return onion_shortcut_response("notification_type's value is invalid", HTTP_BAD_REQUEST, req, res);
    }
	//onion_response_printf(res,"<p>Client description: %s",onion_request_get_client_description(req));
	return OCS_PROCESSED;
}


onion *o=NULL;

static void shutdown_server(int _){
	if (o)
		onion_listen_stop(o);
}

int main(int argc, char **argv){
	signal(SIGINT,shutdown_server);
	signal(SIGTERM,shutdown_server);

	ONION_VERSION_IS_COMPATIBLE_OR_ABORT();

	o=onion_new(O_POOL);
	onion_set_timeout(o, 5000);
	onion_set_hostname(o,"0.0.0.0");
	onion_set_port(o, "9527"); 	
	onion_url *urls=onion_root_url(o);

	onion_url_add(urls, "", index_page);
	onion_url_add(urls, "akong/", index_page);
	onion_url_add(urls, "^(.*)$", hello);

	onion_listen(o);
	onion_free(o);
	return 0;
}
