#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h> /* for mmap    */

#define MAX_SOUND_QUEUE_SIZE 64
char** sound_queue = NULL;
int* front_ptr = NULL;
int* rear_ptr = NULL;

int initialize_queue() {
  sound_queue = mmap(NULL, MAX_SOUND_QUEUE_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
  front_ptr = (int*)mmap(NULL, sizeof(int), PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0); 
  rear_ptr  = (int*)mmap(NULL, sizeof(int), PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0); 
  *front_ptr = 0;
  *rear_ptr = 0;
}

int get_queue_size() {
  if (sound_queue == NULL || front_ptr == NULL || rear_ptr == NULL) {
    return 0;
  }
  return (MAX_SOUND_QUEUE_SIZE + *rear_ptr - *front_ptr) % MAX_SOUND_QUEUE_SIZE;
}

void list_queue_items() {
    printf(
      "Current sound_queue (front_ptr: %d, rear_prt: %d, size: %d, MAX_SOUND_QUEUE_SIZE: %d):\n",
      *front_ptr, *rear_ptr, get_queue_size(), MAX_SOUND_QUEUE_SIZE - 1
    );
    for (int i = *front_ptr; i < *front_ptr + get_queue_size(); ++i) {
        printf("%d: %s\n", i, sound_queue[i % MAX_SOUND_QUEUE_SIZE]);
    }
}

bool enqueue(const char* sound_name) {
  if (get_queue_size() >= MAX_SOUND_QUEUE_SIZE - 1) {
    return false;
    /*
    Per current design, the available slot of the queue is MAX_SOUND_QUEUE_SIZE - 1
    The reason is that front_ptr == rear_ptr could be ambiguous--it can mean either queue is empty or full.
    To aovid this ambiguity, we define front_ptr == rear_ptr as empty and front_ptr + 1 == rear_ptr as full
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

/**
 * Return a pointer to sound_name at front_ptr or NULL in case of empty queue or memory allocation failure.
 * Caller needs to free() the char pointer after use.
*/
char* peek() {
  if (get_queue_size() <= 0) {
    return NULL;
  }
  char* item = malloc((strlen(sound_queue[*front_ptr]) + 1) * sizeof(char));
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
  while(get_queue_size() > 0) {
    dequeue();
  }
  if (sound_queue != NULL) {
    free(sound_queue);
  }
  if (front_ptr != NULL) {
    free(front_ptr);
  }
  if (rear_ptr != NULL) {
    free(rear_ptr);
  }
  sound_queue = NULL;
  front_ptr = NULL;
  rear_ptr = NULL;
}
