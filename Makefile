CC = gcc
CFLAGS = -O2 -Wall -pedantic -Wextra -Wc++-compat
LDFLAGS = -lmicrohttpd -lpthread -lmpg123 -lao -ljson-c
SRC_DIR = ./src


main: pac.out 

pac.out: $(SRC_DIR)/main.c queue.o utils.o
	$(CC) $(SRC_DIR)/main.c queue.o utils.o -o pac.out $(CFLAGS) $(LDFLAGS)

queue.o: $(SRC_DIR)/queue.c $(SRC_DIR)/queue.h
	$(CC) $(SRC_DIR)/queue.c -c $(OPTS)

utils.o: $(SRC_DIR)/utils.c $(SRC_DIR)/utils.h
	$(CC) $(SRC_DIR)/utils.c -c $(OPTS)

.PHONY:
clean:
	rm *.out *.o $(SRC_DIR)/*.o