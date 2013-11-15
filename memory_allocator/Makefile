HEADERS = memalloc.h

default: memalloc

memalloc.o: memalloc.c $(HEADERS)
	gcc -c -g memalloc.c

memalloc: memalloc.o
	gcc -g memalloc.o -o memalloc

clean:
	rm -f memalloc.o memalloc
