#include <onion/log.h>
#include <pthread.h>
/* play MP3 files */
#include <ao/ao.h>
#include <mpg123.h>

#include "utils.h"
#include "queue.h"

const char* sound_repository_path;
const char* pac_username;
const char* pac_passwd;
pthread_mutex_t lock;

bool authenticate(onion_request *req, onion_response *res) {
  const char *auth_header = onion_request_get_header(req, "Authorization");
  char *auth = NULL;
  char *supplied_username = NULL;
  char *supplied_passwd = NULL;
  bool is_authed = false;
  if (auth_header && strncmp(auth_header, "Basic", 5) == 0) {
    auth = onion_base64_decode(&auth_header[6], NULL);
    supplied_username = auth;
    int i = 0;
    while (auth[i] != '\0' && auth[i] != ':') { i++; }    
    if (auth[i] == ':') {
        auth[i] = '\0'; // supplied_username is set to auth, we terminate auth to make supplied_username work
        supplied_passwd = &auth[i + 1];
    }
    if (
      supplied_username != NULL && supplied_passwd != NULL &&
      strncmp(supplied_username, pac_username, strlen(pac_username)) == 0 &&
      strncmp(supplied_passwd, pac_passwd, strlen(pac_passwd)) == 0
    ) {
      // C evaluates the && and || in a "short-circuit" manner. That is, for &&, if A in (A && B)
      // is false, B will NOT be evaluated.
      return true;
    }
  } 

  const char RESPONSE_UNAUTHORIZED[] = "<h1>Unauthorized access</h1>";
  // Not authorized. Ask for it.
  char temp[256];
  sprintf(temp, "Basic realm=PAC");
  onion_response_set_header(res, "WWW-Authenticate", temp);
  onion_response_set_code(res, HTTP_UNAUTHORIZED);
  onion_response_set_length(res, sizeof(RESPONSE_UNAUTHORIZED));
  onion_response_write(res, RESPONSE_UNAUTHORIZED, sizeof(RESPONSE_UNAUTHORIZED));
  return false;
}

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
          onion_log_stderr(O_INFO, "utils.c", 80, "sound_name_queue cleared, thread quited\n");
          break;
        }

        char* sound_name = peek();
        if (sound_name == NULL) {
          onion_log_stderr(
              O_ERROR, "utils.c", 80,
              "Failed to peek() a non-empty queue. The 1st item will be directly dequeue()'ed\n", sound_name
          );
          pthread_mutex_lock(&lock);
          dequeue();
          continue;
        }
        if (strnlen(sound_name, NAME_MAX) >= NAME_MAX) {
          onion_log_stderr(
              O_ERROR, "utils.c", 90,
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
          onion_log_stderr(O_ERROR, "utils.c", 100, "sound_realpath == NULL. It will be directly dequeue()'ed\n");
        }
        FILE *fptr;
        if ((fptr = fopen(sound_realpath, "r"))) {
          fclose(fptr);
          onion_log_stderr(
            O_INFO, "utils.c", 110, "Currently playing: [%s], current sound_queue_size: %d\n", sound_realpath, qs
          );
          play_sound(sound_realpath);
        } else {
          onion_log_stderr(
            O_ERROR, "utils.c", 110, "sound_realpath is not NULL but the file does not exist. dequeue()'ed\n"
          );
        }        
        pthread_mutex_lock(&lock);
        dequeue();
    }
}