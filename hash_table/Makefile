HEADERS = hash_table.h

default: hash_table

hash_table.o: hash_table.c $(HEADERS)
	gcc -c hash_table.c

hash_table: hash_table.o
	gcc hash_table.o -o hash_table

clean:
	rm -f hash_table.o hash_table
