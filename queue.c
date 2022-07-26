#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h> /* for mmap    */

#define MAX_SOUND_QUEUE_SIZE 8
char** sound_queue;
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
  return (MAX_SOUND_QUEUE_SIZE + *rear_ptr - *front_ptr) % MAX_SOUND_QUEUE_SIZE;
}

void list_queue_items() {
    printf("Current sound_queue (front_ptr: %d, rear_prt: %d, size: %d):\n", *front_ptr, *rear_ptr, get_queue_size());
    for (int i = *front_ptr; i < *front_ptr + get_queue_size(); ++i) {
        printf("%d: %s\n", i, sound_queue[i % MAX_SOUND_QUEUE_SIZE]);
    }
}

bool enqueue(const char* sound_name) {
  if (get_queue_size() >= MAX_SOUND_QUEUE_SIZE - 1) {
    return false;
  }
  sound_queue[*rear_ptr] = malloc((strlen(sound_name) + 1) * sizeof(char));
  strcpy(sound_queue[*rear_ptr], sound_name);
  ++(*rear_ptr);
  *rear_ptr %= MAX_SOUND_QUEUE_SIZE;
  list_queue_items();
  return true;
}

/**
 * Caller needs to free() the char pointer
*/
char* peek() {
  if (get_queue_size() <= 0) {
    return NULL;
  }
  char* item = malloc((strlen(sound_queue[*front_ptr]) + 1) * sizeof(char));
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