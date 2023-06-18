#include "queue.h"

char **sound_queue = NULL;
int *front_ptr = NULL;
int *rear_ptr = NULL;

int initialize_queue() {
  sound_queue = malloc(MAX_SOUND_QUEUE_SIZE * sizeof(char *));
  front_ptr = malloc(sizeof(int));
  rear_ptr = malloc(sizeof(int));
  *front_ptr = 0;
  *rear_ptr = 0;
}

int get_queue_size() {
  if (sound_queue == NULL || front_ptr == NULL || rear_ptr == NULL) {
    return 0;
  }
  return (MAX_SOUND_QUEUE_SIZE + *rear_ptr - *front_ptr) % MAX_SOUND_QUEUE_SIZE;
}

char *list_queue_items() {
  char *queue_str =
      malloc(MAX_SOUND_QUEUE_SIZE * (NAME_MAX + 32) * sizeof(char));
  size_t queue_str_len = 0;

  if (queue_str == NULL) {
    return NULL;
  }
  queue_str_len +=
      sprintf(queue_str + queue_str_len, "=====\n", *front_ptr, *rear_ptr,
              get_queue_size(), MAX_SOUND_QUEUE_SIZE - 1);
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

bool enqueue(const char *sound_name) {
  if (sound_queue == NULL || get_queue_size() >= MAX_SOUND_QUEUE_SIZE - 1) {
    return false;
    /*
    Per current design, the available slot of the queue is MAX_SOUND_QUEUE_SIZE
    - 1 The reason is that front_ptr == rear_ptr could be ambiguous--it can mean
    either queue is empty or full. To aovid this ambiguity, we define front_ptr
    == rear_ptr as empty and front_ptr + 1 == rear_ptr as full
    */
  }
  sound_queue[*rear_ptr] = malloc((strlen(sound_name) + 1) * sizeof(char));
  if (sound_queue[*rear_ptr] == NULL) {
    return false;
  }
  strcpy(sound_queue[*rear_ptr], sound_name);
  ++(*rear_ptr);
  *rear_ptr %= MAX_SOUND_QUEUE_SIZE;
  list_queue_items();
  return true;
}

char *peek() {
  if (get_queue_size() <= 0) {
    return NULL;
  }
  char *item = malloc((strlen(sound_queue[*front_ptr]) + 1) * sizeof(char));
  if (item == NULL) {
    return NULL;
  }
  strcpy(item, sound_queue[*front_ptr]);
  return item;
}

void dequeue() {
  if (get_queue_size() <= 0) {
    return;
  }
  free(sound_queue[*front_ptr]);
  ++(*front_ptr);
  (*front_ptr) %= MAX_SOUND_QUEUE_SIZE;
}

void finalize_queue() {
  while (get_queue_size() > 0) {
    dequeue();
  }
  free(sound_queue);
  free(front_ptr);
  free(rear_ptr);
  sound_queue = NULL;
  front_ptr = NULL;
  rear_ptr = NULL;
}
