HEADERS = lru.h
LIBS = -lssl -lcrypto

default: lru_cache

lru_cache.o: lru_cache.c $(HEADERS)
	gcc -c lru_cache.c $(LIBS)

lru_cache: lru_cache.o
	gcc lru_cache.o -o lru_cache $(LIBS)

clean:
	rm -f lru_cache.o lru_cache
