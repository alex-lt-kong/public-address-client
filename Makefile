main: pac.c queue.o
	gcc pac.c queue.o -o pac.out -lonion -lpthread -lmpg123 -lao -ljson-c

queue.o: queue.c queue.h
	gcc queue.c -c