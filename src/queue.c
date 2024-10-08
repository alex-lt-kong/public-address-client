#include "queue.h"
#include "utils.h"

#include <errno.h>
#include <limits.h>
#include <linux/limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/syslog.h>
#include <syslog.h>

char **sound_queue = NULL;
int *front_ptr = NULL;
int *rear_ptr = NULL;
pthread_mutex_t lock;

int pacq_initialize_queue() {
  // To make pacq_get_queue_size()/pacq_enqueue()/dequeue() work correctly, we
  // must use (MAX_SOUND_QUEUE_SIZE + 1) instead of MAX_SOUND_QUEUE_SIZE here.
  sound_queue = (char **)malloc((MAX_SOUND_QUEUE_SIZE + 1) * sizeof(char *));
  front_ptr = (int *)malloc(sizeof(int));
  rear_ptr = (int *)malloc(sizeof(int));
  if (sound_queue == NULL || front_ptr == NULL || rear_ptr == NULL) {
    SYSLOG_ERR("malloc() failed: %d(%s)", errno, strerror(errno));
    free(sound_queue);
    free(rear_ptr);
    free(front_ptr);
    return -1;
  }
  int retval = pthread_mutex_init(&lock, NULL);
  if (retval != 0) {
    SYSLOG_ERR("pthread_mutex_init() failed: %d", retval);
    free(sound_queue);
    free(rear_ptr);
    free(front_ptr);
    return -2;
  }
  *front_ptr = 0;
  *rear_ptr = 0;
  return 0;
}

ssize_t pacq_get_queue_size() {
  int r;
  ssize_t queue_sz = 0;
  if ((r = pthread_mutex_lock(&lock)) != 0) {
    SYSLOG_ERR("pthread_mutex_lock() failed: %d", r);
    queue_sz = -1;
    goto err_pthread_mutex_lock;
  }

  if (sound_queue == NULL || front_ptr == NULL || rear_ptr == NULL) {
    SYSLOG_ERR("Unexpected internal sound_queue state: not initialized");
    queue_sz = -1;
  } else {
    // To make pacq_get_queue_size()/pacq_enqueue()/dequeue() work correctly, we
    // must use (MAX_SOUND_QUEUE_SIZE + 1) instead of MAX_SOUND_QUEUE_SIZE here.
    queue_sz = ((MAX_SOUND_QUEUE_SIZE + 1) + *rear_ptr - *front_ptr) %
               (MAX_SOUND_QUEUE_SIZE + 1);
  }
  if ((r = pthread_mutex_unlock(&lock)) != 0) {
    SYSLOG_ERR("pthread_mutex_unlock() failed: %d", r);
  }
err_pthread_mutex_lock:
  return queue_sz;
}

/*
char *list_queue_items() {
  char *queue_str =
      (char *)malloc(MAX_SOUND_QUEUE_SIZE * (NAME_MAX + 32) * sizeof(char));
  size_t queue_str_len = 0;

  if (queue_str == NULL) {
    SYSLOG_ERR( "malloc() failed");
    return NULL;
  }
  queue_str_len += sprintf(queue_str + queue_str_len,
                           "===== sound_queue (front_ptr: %d, rear_ptr: %d, "
                           "size: %d, MAX_SOUND_QUEUE_SIZE: %d) =====\n",
                           *front_ptr, *rear_ptr, pacq_get_queue_size(),
                           MAX_SOUND_QUEUE_SIZE - 1);
  for (int i = *front_ptr; i < *front_ptr + pacq_get_queue_size(); ++i) {
    queue_str_len += sprintf(queue_str + queue_str_len, "%d: %s\n", i,
                             sound_queue[i % MAX_SOUND_QUEUE_SIZE]);
  }
  queue_str_len += sprintf(queue_str + queue_str_len,
                           "===== sound_queue (front_ptr: %d, rear_ptr: %d, "
                           "size: %d, MAX_SOUND_QUEUE_SIZE: %d) =====\n",
                           *front_ptr, *rear_ptr, pacq_get_queue_size(),
                           MAX_SOUND_QUEUE_SIZE - 1);
  return queue_str;
}
*/

int pacq_enqueue(const char *sound_name) {
  int r;
  int retval = 0;
  ssize_t queue_size = pacq_get_queue_size();
  if (queue_size > MAX_SOUND_QUEUE_SIZE || queue_size < 0) {
    SYSLOG_ERR("unexpected sound_queue internal state, queue_size: %zd",
               queue_size);
    return -1;
  }
  if (queue_size == MAX_SOUND_QUEUE_SIZE) {
    syslog(LOG_WARNING,
           "sound_queue full, queue_size: %zd, MAX_SOUND_QUEUE_SIZE: %d",
           queue_size, MAX_SOUND_QUEUE_SIZE);
    return -1;
  }
  if ((r = pthread_mutex_lock(&lock)) != 0) {
    SYSLOG_ERR("pthread_mutex_lock() failed: %d", r);
    retval = -1;
    goto err_pthread_mutex_lock;
  }
  sound_queue[*rear_ptr] =
      (char *)malloc((strlen(sound_name) + 1) * sizeof(char));
  if (sound_queue[*rear_ptr] == NULL) {
    SYSLOG_ERR("malloc() failed");
    retval = -2;
    goto err_malloc_failed;
  }
  strcpy(sound_queue[*rear_ptr], sound_name);
  ++(*rear_ptr);
  *rear_ptr %= (MAX_SOUND_QUEUE_SIZE + 1);
err_malloc_failed:
  if ((r = pthread_mutex_unlock(&lock)) != 0) {
    SYSLOG_ERR("pthread_mutex_unlock() failed: %d", r);
  }
err_pthread_mutex_lock:
  return retval;
}

char *pacq_peek() {
  int r;
  if (pacq_get_queue_size() <= 0) {
    return NULL;
  }
  if ((r = pthread_mutex_lock(&lock)) != 0) {
    SYSLOG_ERR("pthread_mutex_lock() failed: %d", r);
  }
  char *item =
      (char *)malloc((strlen(sound_queue[*front_ptr]) + 1) * sizeof(char));
  if (item == NULL) {
    SYSLOG_ERR("malloc() failed");
    if ((r = pthread_mutex_unlock(&lock)) != 0) {
      SYSLOG_ERR("pthread_mutex_unlock() failed: %d", r);
    }
    return NULL;
  }
  strcpy(item, sound_queue[*front_ptr]);
  if ((r = pthread_mutex_unlock(&lock)) != 0) {
    SYSLOG_ERR("pthread_mutex_unlock() failed: %d", r);
  }
  return item;
}

int pacq_dequeue() {
  int retval = 0;
  int res;
  if (pacq_get_queue_size() <= 0) {
    retval = -1;
    goto err_get_queue_size;
  }
  if ((res = pthread_mutex_lock(&lock)) != 0) {
    SYSLOG_ERR("pthread_mutex_lock() failed: %d", res);
    retval = -1;
    goto err_pthread_mutex_lock;
  }
  free(sound_queue[*front_ptr]);
  ++(*front_ptr);
  (*front_ptr) %= (MAX_SOUND_QUEUE_SIZE + 1);
  if ((res = pthread_mutex_unlock(&lock)) != 0) {
    SYSLOG_ERR("pthread_mutex_unlock() failed: %d", res);
  }
err_pthread_mutex_lock:
err_get_queue_size:
  return retval;
}

void pacq_finalize_queue() {
  ssize_t queue_sz;
  while (1) {
    queue_sz = pacq_get_queue_size();
    if (queue_sz > 0) {
      pacq_dequeue();
    } else if (queue_sz == 0) {
      SYSLOG_INFO("sound_queue cleared.");
      break;
    } else {
      SYSLOG_ERR("sound_queue in an unexpected state.");
      break;
    }
  }
  int r;
  if ((r = pthread_mutex_destroy(&lock)) != 0) {
    SYSLOG_ERR("pthread_mutex_destroy() failed: %d", r);
  }
  free(sound_queue);
  free(front_ptr);
  free(rear_ptr);
  sound_queue = NULL;
  front_ptr = NULL;
  rear_ptr = NULL;
}
