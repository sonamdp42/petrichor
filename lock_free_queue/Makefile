HEADERS = lf_queue.h
LIBS = -lpthread

default: lf_queue_test

lf_queue_test.o: lf_queue.c lf_queue_test.c $(HEADERS)
	gcc -c lf_queue_test.c lf_queue.c $(LIBS)

lf_queue.o: lf_queue.c $(HEADERS)
	gcc -c lf_queue.c $(LIBS)

lf_queue_test: lf_queue.o lf_queue_test.o
	gcc lf_queue.o lf_queue_test.o -o lf_queue_test $(LIBS)

clean:
	rm -f *.o lf_queue_test
