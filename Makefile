CC = gcc
CFLAGS = -O3 -Wall -pedantic -Wextra -Wc++-compat
LDFLAGS = -lmicrohttpd -lpthread -lmpg123 -lao -ljson-c
SRC_DIR = ./src
BUILD_DIR = build

#SANITIZER = -fsanitize=address -g
#VALGRIND = -ggdb3

main: pac 

pac: $(SRC_DIR)/main.c queue.o utils.o http_service.o
	@mkdir -p $(BUILD_DIR)
	$(CC) $(SRC_DIR)/main.c $(BUILD_DIR)/queue.o $(BUILD_DIR)/utils.o $(BUILD_DIR)/http_service.o -o $(BUILD_DIR)/pac $(CFLAGS) $(LDFLAGS) $(SANITIZER)

queue.o: $(SRC_DIR)/queue.c $(SRC_DIR)/queue.h
	$(CC) $(SRC_DIR)/queue.c -c $(CFLAGS) $(SANITIZER) -o $(BUILD_DIR)/queue.o

utils.o: $(SRC_DIR)/utils.c $(SRC_DIR)/utils.h
	$(CC) $(SRC_DIR)/utils.c -c $(CFLAGS) $(SANITIZER) -o $(BUILD_DIR)/utils.o

http_service.o: $(SRC_DIR)/http_service.c $(SRC_DIR)/http_service.h
	$(CC) $(SRC_DIR)/http_service.c -c $(CFLAGS) $(SANITIZER) -o $(BUILD_DIR)/http_service.o

.PHONY:
clean:
	rm $(BUILD_DIR)/*.o
	rm $(BUILD_DIR)/pac
