main: pac.c queue.o utils.o
	gcc pac.c queue.o utils.o -O3 -o pac.out -lonion -lpthread -lmpg123 -lao -ljson-c

queue.o: queue.c queue.h
	gcc queue.c -c -O3

utils.o: utils.c utils.h
	gcc utils.c -c -O3

clean:
	rm *.out
	rn *.o