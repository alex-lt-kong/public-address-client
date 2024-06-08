#include "utils.h"
#include "queue.h"

/* play MP3 files */
#include <ao/ao.h>
#include <dirent.h>
#include <json-c/json_object.h>
#include <mpg123.h>

#include <libgen.h> /* dirname() */
#include <linux/limits.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <syslog.h>

char gv_sound_repository_path[PATH_MAX + 1];
char gv_http_auth_username[NAME_MAX + 1];
char http_auth_password[NAME_MAX + 1];
char gv_interface[NAME_MAX + 1];

// gv_ssl_key and gv_ssl_crt are string, not bytes
char gv_ssl_key[SSL_FILE_BUFF_SIZE];
char gv_ssl_crt[SSL_FILE_BUFF_SIZE];
int gv_port;

int play_sound(const char *sound_path) {
  int ret_val = 0;
  // This function an its variants seems everywhere on the Internet, my version
  // comes from:
  // https://hzqtc.github.io/2012/05/play-mp3-with-libmpg123-and-libao.html my
  // understanding is that mpg123 is responsible for decoding and libao is
  // respobsible for making sounds from decoded raw music bytes.
  // mpg123 official doc: https://www.mpg123.de/api/
  mpg123_handle *mh;
  unsigned char *buffer;
  size_t buffer_size;
  size_t done;
  int err;

  int driver_id;
  ao_device *dev;

  ao_sample_format format;
  int channels, encoding;
  long rate;

  (void)ao_initialize();
  driver_id = ao_default_driver_id();
  if (driver_id < 0) {
    syslog(LOG_ERR,
           "ao_default_driver_id() failed to find an available driver");
    ret_val = -1;
    goto err_ao_default_driver_id;
  }

  // Useless no-op that used to do initialization work.
  // Now this function really does nothing anymore. The only reason to call it
  // is to be compatible with old versions of the library that still require it.
  ret_val = mpg123_init();
  if (ret_val != MPG123_OK) {
    syslog(LOG_ERR, "mpg123_init() failed, returned: %d", ret_val);
    ret_val = -1;
    goto err_mpg123_init;
  }

  mh = mpg123_new(NULL, &err);
  if (mh == NULL) {
    syslog(LOG_ERR,
           "failed to create an mpg123_handle by calling mpg123_new(). "
           "Error code: %d",
           err);
    ret_val = -1;
    goto err_mpg123_new;
  }

  // mpg123's doc doesn't seems to mention that this function will fail.
  buffer_size = mpg123_outblock(mh);
  buffer = (unsigned char *)malloc(buffer_size * sizeof(unsigned char));
  if (buffer == NULL) {
    syslog(LOG_ERR, "malloc() buffer failed");
    ret_val = -1;
    goto err_buffer_malloc;
  }
  /* open the file and get the decoding format */
  ret_val = mpg123_open(mh, sound_path);
  if (ret_val != MPG123_OK) {
    syslog(LOG_ERR, "mpg123_open() failed, err: %d", ret_val);
    ret_val = -1;
    goto err_mpg123_open;
  }

  ret_val = mpg123_getformat(mh, &rate, &channels, &encoding);
  if (ret_val != MPG123_OK) {
    syslog(LOG_ERR, "mpg123_getformat() failed, err: %d", ret_val);
    ret_val = -1;
    goto err_mpg123_getformat;
  }

  /* set the output format and open the output device */
  format.bits = mpg123_encsize(encoding) * 8;
  if (format.bits == 0) {
    syslog(LOG_ERR,
           "mpg123_encsize() returns 0, meaning that format is not supported");
    ret_val = -1;
    goto err_mpg123_encsize;
  }
  format.rate = rate;
  format.channels = channels;
  format.byte_format = AO_FMT_NATIVE;
  format.matrix = 0;
  dev = ao_open_live(driver_id, &format, NULL);
  // This function call is a common point of failure, doc here:
  // https://xiph.org/ao/doc/ao_open_live.html
  if (dev == NULL) {
    syslog(LOG_ERR, "ao_open_live() returns NULL: %d (%s)", errno,
           strerror(errno));
    ret_val = -1;
    goto err_ao_open_live;
  }

  /* decode and play */
  while (mpg123_read(mh, buffer, buffer_size, &done) == MPG123_OK) {
    if (ao_play(dev, (char *)buffer, done) == 0) {
      syslog(LOG_ERR, "ao_play() failed");
      break;
    }
  }

  if (ao_close(dev) == 0) {
    syslog(LOG_ERR, "ao_close() failed");
  }
err_ao_open_live:
err_mpg123_encsize:
err_mpg123_getformat:
  if (mpg123_close(mh) != MPG123_OK) {
    syslog(LOG_ERR, "mpg123_close() failed");
  }
err_mpg123_open:
  /* clean up */
  (void)free(buffer);
err_buffer_malloc:
  // mpg123_delete accepts either a valid handle or NULL
  (void)mpg123_delete(mh);
err_mpg123_new:
err_mpg123_init:
  (void)mpg123_exit();
err_ao_default_driver_id:
  (void)ao_shutdown();
  return ret_val;
}

void *handle_sound_name_queue() {
  char *sound_realpath = NULL;
  while (1) {
    size_t qs = pacq_get_queue_size();

    free(sound_realpath);
    if (qs == 0) {
      syslog(
          LOG_INFO,
          "sound_name_queue cleared, handle_sound_name_queue() thread quited");
      break;
    }
    sound_realpath = pacq_peek();
    if (sound_realpath == NULL) {
      syslog(LOG_ERR,
             "Failed to peek() a non-empty queue. The 1st item will be "
             "directly pacq_dequeue()'ed");

      pacq_dequeue();
      continue;
    }
    if (strnlen(sound_realpath, PATH_MAX) >= PATH_MAX) {
      syslog(
          LOG_ERR,
          "sound_realpath [%s] too long. It will be directly pacq_dequeue()'ed",
          sound_realpath);
      pacq_dequeue();
      continue;
    }

    syslog(LOG_INFO, "Currently playing: [%s], current sound_queue_size: %lu",
           sound_realpath, qs);
    // We dont check file accessibility here, this is checked on index_page()
    // mpg123/ao will return if the file does not exist without breaking the
    // program
    int retval = play_sound(sound_realpath);
    pacq_dequeue();
    if (retval != 0) {
      syslog(LOG_ERR,
             "Failed to play: [%s], this sound will be removed from "
             "sound_queue anyway, current queue_size: %ld",
             sound_realpath, pacq_get_queue_size());
    } else {
      // use to debug potential deadlock
      syslog(LOG_INFO, "[%s] played successfully, current queue_size: %ld",
             sound_realpath, pacq_get_queue_size());
    }
  }
  return (void *)NULL;
}

bool is_file_accessible(const char *file_path) {
  FILE *fptr;
  if ((fptr = fopen(file_path, "r"))) {
    fclose(fptr);
    return true;
  } else {
    return false;
  }
}

int load_ssl_key_or_crt(const char *path, unsigned char **out_content) {
  FILE *fp;
  int retval = 0;
  fp = fopen(path, "rb");
  if (fp == NULL) {
    syslog(LOG_ERR, "%s.%d: Failed to fopen() path [%s]: %d(%s)", __FILE__,
           __LINE__, path, errno, strerror(errno));
    retval = -1;
    goto err_fopen;
  }

  size_t bytes_read =
      fread(out_content, sizeof(unsigned char), SSL_FILE_BUFF_SIZE, fp);
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
    syslog(LOG_ERR, "%s.%d: sound_repository [%s] is either NULL or too long",
           __FILE__, __LINE__, sound_repository_path);
    return -1;
  }
  DIR *dir = opendir(sound_repository_path);
  if (dir) { // exist
    closedir(dir);
  } else {
    syslog(LOG_ERR, "%s.%d: sound_repository [%s] is inaccessible", __FILE__,
           __LINE__, sound_repository_path);
    return -2;
  }
  return 0;
}

int load_values_from_json(const char *settings_path) {

  int retval = 0;
  json_object *root = json_object_from_file(settings_path);
  if (root == NULL) {
    syslog(LOG_ERR, "%s.%d: json_object_from_file(%s) returned NULL: %s",
           __FILE__, __LINE__, settings_path, json_util_get_last_err());
    retval = -1;
    goto err_json_parsing;
  }
  json_object *root_app;
  json_object_object_get_ex(root, "app", &root_app);
  json_object *root_app_port;
  json_object_object_get_ex(root_app, "port", &root_app_port);
  json_object *root_app_gv_interface;
  json_object_object_get_ex(root_app, "interface", &root_app_gv_interface);
  json_object *root_app_sound_repo_path;
  json_object_object_get_ex(root_app, "sound_repo_path",
                            &root_app_sound_repo_path);
  json_object *root_app_username;
  json_object_object_get_ex(root_app, "username", &root_app_username);
  json_object *root_app_passwd;
  json_object_object_get_ex(root_app, "passwd", &root_app_passwd);
  json_object *root_app_ssl;
  json_object_object_get_ex(root_app, "ssl", &root_app_ssl);
  json_object *root_app_ssl_enabled;
  json_object_object_get_ex(root_app_ssl, "enabled", &root_app_ssl_enabled);
  json_object *root_app_ssl_crt_path;
  json_object_object_get_ex(root_app_ssl, "crt_path", &root_app_ssl_crt_path);
  json_object *root_app_ssl_key_path;
  json_object_object_get_ex(root_app_ssl, "key_path", &root_app_ssl_key_path);

  strncpy(gv_sound_repository_path,
          json_object_get_string(root_app_sound_repo_path), PATH_MAX);
  if (check_sound_repo_validity(gv_sound_repository_path) < 0) {
    retval = -2;
    goto err_invalid_config;
  }

  strncpy(gv_http_auth_username, json_object_get_string(root_app_username),
          NAME_MAX);
  strncpy(http_auth_password, json_object_get_string(root_app_passwd),
          NAME_MAX);
  json_bool ssl_enabled = json_object_get_boolean(root_app_ssl_enabled);
  const char *ssl_crt_path = json_object_get_string(root_app_ssl_crt_path);
  const char *ssl_key_path = json_object_get_string(root_app_ssl_key_path);

  if (strlen(gv_http_auth_username) == 0 || strlen(http_auth_password) == 0 ||
      (ssl_enabled && (ssl_crt_path == NULL || ssl_key_path == NULL))) {
    syslog(LOG_ERR, "%s.%d: Some required values are not provided", __FILE__,
           __LINE__);
    retval = -3;
    goto err_invalid_config;
  }
  if (ssl_enabled) {
    if (load_ssl_key_or_crt(ssl_crt_path, (unsigned char **)&gv_ssl_crt) < 0) {
      syslog(LOG_ERR, "%s.%d: Failed to read SSL certificate file", __FILE__,
             __LINE__);
      retval = -4;
      goto err_invalid_config;
    }
    if (load_ssl_key_or_crt(ssl_key_path, (unsigned char **)&gv_ssl_key) < 0) {
      syslog(LOG_ERR, "%s.%d: Failed to read SSL key file", __FILE__, __LINE__);
      retval = -5;
      goto err_invalid_config;
    }
    if (strlen(gv_ssl_crt) == 0 || strlen(gv_ssl_key) == 0) {
      syslog(LOG_ERR, "%s.%d: Either gv_ssl_crt or gv_ssl_key is empty",
             __FILE__, __LINE__);
      retval = -6;
      goto err_invalid_config;
    }
  } else {
    gv_ssl_crt[0] = '\0';
    gv_ssl_key[0] = '\0';
  }
  strncpy(gv_interface, json_object_get_string(root_app_gv_interface),
          NAME_MAX);
  gv_port = atoi(json_object_get_string(root_app_port));
err_invalid_config:
  json_object_put(root);
err_json_parsing:
  return retval;
}