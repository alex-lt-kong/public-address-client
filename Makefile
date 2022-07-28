main: pac.c queue.o utils.o
	gcc pac.c queue.o utils.o -o pac.out -lonion -lpthread -lmpg123 -lao -ljson-c

queue.o: queue.c queue.h
	gcc queue.c -c

utils.o: utils.c utils.h
	gcc utils.c -c

clean:
	rm *.out
	rn *.o