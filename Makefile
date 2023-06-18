CC = clang
SRC_DIR = ./src
OPTS = -O2 -Wall -pedantic -Wextra -Wc++-compat

main: $(SRC_DIR)/main.c $(SRC_DIR)/queue.o $(SRC_DIR)/utils.o
	$(CC) $(SRC_DIR)/main.c $(SRC_DIR)/queue.o $(SRC_DIR)/utils.o -o ./pac.out -lmicrohttpd -lpthread -lmpg123 -lao -ljson-c $(OPTS)

queue.o: $(SRC_DIR)/queue.c $(SRC_DIR)/queue.h
	$(CC) $(SRC_DIR)/queue.c -c $(OPTS)

utils.o: $(SRC_DIR)/utils.c $(SRC_DIR)/utils.h
	$(CC) $(SRC_DIR)/utils.c -c $(OPTS)

clean:
	rm *.out *.o $(SRC_DIR)/*.o