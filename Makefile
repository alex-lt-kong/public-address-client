CC = gcc
CFLAGS = -O2 -Wall -pedantic -Wextra -Wc++-compat
LDFLAGS = -lmicrohttpd -lpthread -lmpg123 -lao -ljson-c
SRC_DIR = ./src
SANITIZER = -fsanitize=address -g

main: pac.out 

pac.out: $(SRC_DIR)/main.c queue.o utils.o
	$(CC) $(SRC_DIR)/main.c queue.o utils.o -o pac.out $(CFLAGS) $(LDFLAGS) $(SANITIZER)

queue.o: $(SRC_DIR)/queue.c $(SRC_DIR)/queue.h
	$(CC) $(SRC_DIR)/queue.c -c $(CFLAGS)  $(SANITIZER)

utils.o: $(SRC_DIR)/utils.c $(SRC_DIR)/utils.h
	$(CC) $(SRC_DIR)/utils.c -c $(CFLAGS)  $(SANITIZER)

.PHONY:
clean:
	rm *.out *.o $(SRC_DIR)/*.o
