main: ./src/pac.c ./src/queue.o ./src/utils.o
	gcc ./src/pac.c ./src/queue.o ./src/utils.o -O3 -o ./pac.out -lonion -lpthread -lmpg123 -lao -ljson-c

queue.o: ./src/queue.c ./src/queue.h
	gcc ./src/queue.c -c -O3

utils.o: ./src/utils.c ./src/utils.h
	gcc ./src/utils.c -c -O3

clean:
	rm *.out *.o ./src/*.out ./src/*.o