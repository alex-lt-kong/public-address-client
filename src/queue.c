#include <linux/limits.h>
#include <syslog.h>

#include "queue.h"

char **sound_queue = NULL;
int *front_ptr = NULL;
int *rear_ptr = NULL;
pthread_mutex_t lock;

int initialize_queue() {
  sound_queue = (char **)malloc(MAX_SOUND_QUEUE_SIZE * sizeof(char *));
  front_ptr = (int *)malloc(sizeof(int));
  rear_ptr = (int *)malloc(sizeof(int));
  if (sound_queue == NULL || front_ptr == NULL || rear_ptr == NULL) {
    fprintf(stderr, "malloc() failed\n");
    free(sound_queue);
    free(rear_ptr);
    free(front_ptr);
    return -1;
  }
  int retval = pthread_mutex_init(&lock, NULL);
  if (retval != 0) {
    syslog(LOG_ERR, "pthread_mutex_init() failed: %d", retval);
    free(sound_queue);
    free(rear_ptr);
    free(front_ptr);
    return -2;
  }
  *front_ptr = 0;
  *rear_ptr = 0;
  return 0;
}

size_t get_queue_size() {
  int r;
  if ((r = pthread_mutex_lock(&lock)) != 0) {
    syslog(LOG_ERR, "pthread_mutex_lock() failed: %d", r);
  }

  if (sound_queue == NULL || front_ptr == NULL || rear_ptr == NULL) {
    return 0;
  }
  size_t sz =
      (MAX_SOUND_QUEUE_SIZE + *rear_ptr - *front_ptr) % MAX_SOUND_QUEUE_SIZE;

  if ((r = pthread_mutex_unlock(&lock)) != 0) {
    syslog(LOG_ERR, "pthread_mutex_unlock() failed: %d", r);
  }
  return sz;
}

/*
char *list_queue_items() {
  char *queue_str =
      (char *)malloc(MAX_SOUND_QUEUE_SIZE * (NAME_MAX + 32) * sizeof(char));
  size_t queue_str_len = 0;

  if (queue_str == NULL) {
    syslog(LOG_ERR, "malloc() failed");
    return NULL;
  }
  queue_str_len += sprintf(queue_str + queue_str_len,
                           "===== sound_queue (front_ptr: %d, rear_ptr: %d, "
                           "size: %d, MAX_SOUND_QUEUE_SIZE: %d) =====\n",
                           *front_ptr, *rear_ptr, get_queue_size(),
                           MAX_SOUND_QUEUE_SIZE - 1);
  for (int i = *front_ptr; i < *front_ptr + get_queue_size(); ++i) {
    queue_str_len += sprintf(queue_str + queue_str_len, "%d: %s\n", i,
                             sound_queue[i % MAX_SOUND_QUEUE_SIZE]);
  }
  queue_str_len += sprintf(queue_str + queue_str_len,
                           "===== sound_queue (front_ptr: %d, rear_ptr: %d, "
                           "size: %d, MAX_SOUND_QUEUE_SIZE: %d) =====\n",
                           *front_ptr, *rear_ptr, get_queue_size(),
                           MAX_SOUND_QUEUE_SIZE - 1);
  return queue_str;
}
*/

int enqueue(const char *sound_name) {
  int r;
  if (sound_queue == NULL || get_queue_size() >= MAX_SOUND_QUEUE_SIZE - 1) {
    syslog(LOG_ERR, "unexpected queue internal state");
    return -1;
    /*
    Per current design, the available slot of the queue is MAX_SOUND_QUEUE_SIZE
    - 1 The reason is that front_ptr == rear_ptr could be ambiguous--it can mean
    either queue is empty or full. To aovid this ambiguity, we define front_ptr
    == rear_ptr as empty and front_ptr + 1 == rear_ptr as full
    */
  }
  if ((r = pthread_mutex_lock(&lock)) != 0) {
    syslog(LOG_ERR, "pthread_mutex_lock() failed: %d", r);
  }
  sound_queue[*rear_ptr] =
      (char *)malloc((strlen(sound_name) + 1) * sizeof(char));
  if (sound_queue[*rear_ptr] == NULL) {
    syslog(LOG_ERR, "malloc() failed");
    if ((r = pthread_mutex_unlock(&lock)) != 0) {
      syslog(LOG_ERR, "pthread_mutex_unlock() failed: %d", r);
    }
    return -1;
  }
  strcpy(sound_queue[*rear_ptr], sound_name);
  ++(*rear_ptr);
  *rear_ptr %= MAX_SOUND_QUEUE_SIZE;
  if ((r = pthread_mutex_unlock(&lock)) != 0) {
    syslog(LOG_ERR, "pthread_mutex_unlock() failed: %d", r);
  }
  return 0;
}

char *peek() {
  int r;
  if (get_queue_size() <= 0) {
    return NULL;
  }
  if ((r = pthread_mutex_lock(&lock)) != 0) {
    syslog(LOG_ERR, "pthread_mutex_lock() failed: %d", r);
  }
  char *item =
      (char *)malloc((strlen(sound_queue[*front_ptr]) + 1) * sizeof(char));
  if (item == NULL) {
    syslog(LOG_ERR, "malloc() failed");
    if ((r = pthread_mutex_unlock(&lock)) != 0) {
      syslog(LOG_ERR, "pthread_mutex_unlock() failed: %d", r);
    }
    return NULL;
  }
  strcpy(item, sound_queue[*front_ptr]);
  if ((r = pthread_mutex_unlock(&lock)) != 0) {
    syslog(LOG_ERR, "pthread_mutex_unlock() failed: %d", r);
  }
  return item;
}

void dequeue() {
  int r;
  if (get_queue_size() <= 0) {
    return;
  }
  if ((r = pthread_mutex_lock(&lock)) != 0) {
    syslog(LOG_ERR, "pthread_mutex_lock() failed: %d", r);
  }
  free(sound_queue[*front_ptr]);
  ++(*front_ptr);
  (*front_ptr) %= MAX_SOUND_QUEUE_SIZE;
  if ((r = pthread_mutex_unlock(&lock)) != 0) {
    syslog(LOG_ERR, "pthread_mutex_unlock() failed: %d", r);
  }
}

void finalize_queue() {
  while (get_queue_size() > 0) {
    dequeue();
  }
  int r;
  if ((r = pthread_mutex_destroy(&lock)) != 0) {
    syslog(LOG_ERR, "pthread_mutex_destroy() failed: %d", r);
  }
  free(sound_queue);
  free(front_ptr);
  free(rear_ptr);
  sound_queue = NULL;
  front_ptr = NULL;
  rear_ptr = NULL;
}
