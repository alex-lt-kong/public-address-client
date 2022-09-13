SRC_DIR = ./src

main: $(SRC_DIR)/main.c $(SRC_DIR)/queue.o $(SRC_DIR)/utils.o
	gcc $(SRC_DIR)/main.c $(SRC_DIR)/queue.o $(SRC_DIR)/utils.o -O3 -o ./pac.out -lonion -lpthread -lmpg123 -lao -ljson-c -Wall

queue.o: $(SRC_DIR)/queue.c $(SRC_DIR)/queue.h
	gcc $(SRC_DIR)/queue.c -c -O3 -Wall

utils.o: $(SRC_DIR)/utils.c $(SRC_DIR)/utils.h
	gcc $(SRC_DIR)/utils.c -c -O3 -Wall

clean:
	rm *.out $(SRC_DIR)/*.o