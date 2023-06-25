#include <linux/limits.h>
#include <pthread.h>
#include <syslog.h>

/* play MP3 files */
#include <ao/ao.h>
#include <mpg123.h>

#include "queue.h"
#include "utils.h"

const char *sound_repository_path;
const char *pac_username;
const char *pac_passwd;

int play_sound(const char *sound_path) {
  int ret_val = 0;
  // This function an its variants seems everywhere on the Internet, my version
  // comes from:
  // https://hzqtc.github.io/2012/05/play-mp3-with-libmpg123-and-libao.html my
  // understanding is that mpg123 is responsible for decoding and libao is
  // respobsible for making sounds from decoded raw music bytes.
  // mpg123 official doc: https://www.mpg123.de/api/
  mpg123_handle *mh;
  char *buffer;
  size_t buffer_size;
  size_t done;
  int err;

  int driver_id;
  ao_device *dev;

  ao_sample_format format;
  int channels, encoding;
  long rate;

  /* initializations */
  (void)ao_initialize();
  driver_id = ao_default_driver_id();
  if (driver_id < 0) {
    syslog(LOG_ERR, "ao_default_driver_id() failed to find a available driver");
    ret_val = driver_id;
    goto err_ao_default_driver_id;
  }

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
  buffer = (char *)malloc(buffer_size * sizeof(unsigned char));
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
    if (ao_play(dev, buffer, done) == 0) {
      syslog(LOG_ERR, "ao_play() failed");
      break;
    }
  }

  ao_close(dev);
err_ao_open_live:
err_mpg123_encsize:
err_mpg123_getformat:
  mpg123_close(mh);
err_mpg123_open:
  /* clean up */
  free(buffer);
err_buffer_malloc:
  mpg123_delete(mh);
err_mpg123_new:
err_mpg123_init:
  mpg123_exit();
err_ao_default_driver_id:
  (void)ao_shutdown();
  return ret_val;
}

void *handle_sound_name_queue() {
  char *sound_realpath = NULL;
  while (1) {
    size_t qs = get_queue_size();

    free(sound_realpath);
    if (qs == 0) {
      syslog(
          LOG_INFO,
          "sound_name_queue cleared, handle_sound_name_queue() thread quited");
      break;
    }
    sound_realpath = peek();
    if (sound_realpath == NULL) {
      syslog(LOG_ERR,
             "Failed to peek() a non-empty queue. The 1st item will be "
             "directly dequeue()'ed");

      dequeue();
      continue;
    }
    if (strnlen(sound_realpath, PATH_MAX) >= PATH_MAX) {
      syslog(LOG_ERR,
             "sound_realpath [%s] too long. It will be directly dequeue()'ed",
             sound_realpath);
      dequeue();
      continue;
    }

    syslog(LOG_INFO, "Currently playing: [%s], current sound_queue_size: %d",
           sound_realpath, qs);
    // We dont check file accessibility here, this is checked on index_page()
    // mpg123/ao will return if the file does not exist without breaking the
    // program
    if (play_sound(sound_realpath) != 0) {
      syslog(LOG_ERR, "Failed to play: [%s]", sound_realpath);
    } else {
      // use to debug potential deadlock
      syslog(LOG_INFO, "[%s] played successfully", sound_realpath);
    }

    dequeue();
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
