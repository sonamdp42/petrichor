#include "memalloc.h"

#define INCREMENT_LEN	8192
#define MAGIC		0x4242
#define MIN_BLOCK_SIZE	8

/* Free list */
struct free_list {
	uint32_t size;
	struct free_list *next;
	struct free_list *prev;
};

char * memalloc_head = NULL;
char * memalloc_start = NULL;

/* Always allocate memory in multiples of min block size */
size_t closest_multiple_of_min_block(size_t size)
{
	return (size + (size % MIN_BLOCK_SIZE));
}

void * memalloc(size_t size)
{
	uint32_t magic = MAGIC;
	size_t to_allocate, aligned_size, cur_size, free_size;
	struct free_list flist, *freeList = NULL, *itr = NULL;
	void *prev = NULL, *next = NULL, *ret = NULL, *tmp = NULL;
	size_t min_mem = sizeof(size_t) + sizeof(uint32_t) + sizeof(uint32_t);

	assert(size > 0);

	aligned_size = closest_multiple_of_min_block(size);

	/* First check if memalloc_head is NULL */
	if (!memalloc_head || !memalloc_start) {
		if (aligned_size >= INCREMENT_LEN)
			to_allocate = aligned_size + INCREMENT_LEN;
		else
			to_allocate = INCREMENT_LEN;

		memalloc_start = sbrk(to_allocate);
		if (memalloc_start == (void *) -1) {
			fprintf(stderr, "Error in sbrk(): %s, %d\n", strerror(errno), errno);
			return NULL;
		}

		memset(memalloc_start, 0, to_allocate);

		memcpy(memalloc_start, &aligned_size, sizeof(size_t));
		memcpy(memalloc_start + sizeof(size_t), &magic, sizeof(uint32_t));
		memcpy(memalloc_start + sizeof(size_t) + sizeof(uint32_t) + aligned_size, &magic, sizeof(uint32_t));

		flist.size = INCREMENT_LEN - aligned_size - min_mem;
		flist.next = NULL;
		flist.prev = NULL;

		memalloc_head = memalloc_start + min_mem + aligned_size;
		memcpy(memalloc_head, &flist, sizeof(struct free_list));

		return memalloc_start + min_mem - sizeof(uint32_t);
	}

	freeList = (struct free_list *) memalloc_head;
	itr = freeList;

	while(itr) {
		if (itr->size - min_mem >= aligned_size) {
			free_size = itr->size;
			prev = itr->prev;
			next = itr->next;

			ret = (char *) itr;

			if (aligned_size < itr->size - 2 * min_mem - MIN_BLOCK_SIZE) {
				/* We have enough space for a free slot here. */
				tmp = (char *) itr + aligned_size + min_mem;

				/* Update previous free slot's next pointer */
				if (prev) {
					memcpy(&flist, prev, sizeof(struct free_list));
					flist.next = tmp;
					memcpy(prev, &flist, sizeof(struct free_list));
				}

				/* Update next free slot's prev pointer */
				if (next) {
					memcpy(&flist, next, sizeof(struct free_list));
					flist.prev = tmp;
					memcpy(next, &flist, sizeof(struct free_list));
				}

				/* Add entry for this free slot */
				flist.size = free_size - aligned_size - min_mem;
				flist.prev = prev;
				flist.next = next;
				memset(tmp, 0, sizeof(struct free_list));
				memcpy(tmp, &flist, sizeof(struct free_list));

				if (ret == memalloc_head)
					memalloc_head = tmp;
			} else {
				/* No space for free slot. */
				aligned_size = free_size;

				/* Update previous free slot's next pointer */
				if (prev) {
					memcpy(&flist, prev, sizeof(struct free_list));
					flist.next = next;
					memcpy(prev, &flist, sizeof(struct free_list));
				}

				/* Update next free slot's prev pointer */
				if (next) {
					memcpy(&flist, next, sizeof(struct free_list));
					flist.prev = prev;
					memcpy(next, &flist, sizeof(struct free_list));
				}

				/* Set memalloc_head to next/prev free slot */
				if ((char *)itr == memalloc_head)
					memalloc_head = next;
			}

			memcpy(ret, &aligned_size, sizeof(size_t));
			memcpy(ret + sizeof(size_t), &magic, sizeof(uint32_t));
			memcpy(ret + sizeof(size_t) + sizeof(uint32_t) + aligned_size, &magic, sizeof(uint32_t));

			return ret + min_mem - sizeof(uint32_t);
		}

		if (itr->next)
			itr = itr->next;
		else
			break;
	}

	/* No big enough free slot found, expand memory! */
	if (aligned_size >= INCREMENT_LEN)
		to_allocate = aligned_size + INCREMENT_LEN;
	else
		to_allocate = INCREMENT_LEN;

	ret = sbrk(to_allocate);
	if (ret == (void *) -1) {
		fprintf(stderr, "Error in sbrk(): %s, %d\n", strerror(errno), errno);
		return NULL;
	}

	memset(ret, 0, to_allocate);

	prev = itr->prev;
	next = itr->next;
	free_size = itr->size;

	memcpy(ret, &aligned_size, sizeof(size_t));
	memcpy(ret + sizeof(size_t), &magic, sizeof(uint32_t));
	memcpy(ret + sizeof(size_t) + sizeof(uint32_t) + aligned_size, &magic, sizeof(uint32_t));

	flist.next = NULL;
	flist.prev = itr;
	flist.size = INCREMENT_LEN - aligned_size - min_mem;

	memcpy(ret + min_mem + aligned_size, &flist, sizeof(struct free_list));

	flist.next = ret + min_mem + aligned_size;
	flist.prev = prev;
	flist.size = free_size;

	memcpy(itr, &flist, sizeof(struct free_list));

	return ret + min_mem - sizeof(uint32_t);
}

void memfree(void * data)
{
	size_t length;
	uint32_t magic = MAGIC;
	struct free_list *freeList = NULL, *itr = NULL, *prev = NULL, *next = NULL, flist;

	assert(data);

	memcpy(&length, data - sizeof(size_t) - sizeof(uint32_t), sizeof(size_t));
	assert(length > 0);

	/* Check if Magic is in place -> detect double free/memory corruption */
	if (memcmp(data - sizeof(uint32_t), &magic, sizeof(uint32_t))) {
		fprintf(stderr, "Memory corruption/double free detected! Cannot free memory\n");
		return;
	}

	if (memcmp(data + length, &magic, sizeof(uint32_t))) {
		fprintf(stderr, "Buffer overflow detected! Cannot free memory\n");
		return;
	}

	/* Need to identify prev and next on free list to this slot */
	freeList = (struct free_list *) memalloc_head;
	if (!freeList->next) {
		prev = freeList;
		next = NULL;
	} else {
		itr = freeList;
		while (itr) {
			if (itr < (struct free_list *)data && itr->next > (struct free_list *)data) {
				printf("Found appropriate prev and next!\n");
				prev = itr;
				next = itr->next;
				break;
			}

			itr = itr->next;
		}
	}

	if (prev) {
		memcpy(&flist, prev, sizeof(struct free_list));
		flist.next = data - sizeof(size_t) - sizeof(uint32_t);
		memcpy(prev, &flist, sizeof(struct free_list));
	}

	if (next) {
		memcpy(&flist, next, sizeof(struct free_list));
		flist.prev = data - sizeof(size_t) - sizeof(uint32_t);
		memcpy(next, &flist, sizeof(struct free_list));
	}

	flist.size = length;
	flist.next = next;
	flist.prev = prev;
	memcpy(data - sizeof(size_t) - sizeof(uint32_t), &flist, sizeof(struct free_list));

	return;
}

int main(int argc, char *argv[])
{
	char *ptr1 = NULL, *ptr2 = NULL;

	ptr1 = (char *) memalloc(sizeof(char) * 150);
	if (!ptr1) {
		printf("Error in allocating ptr1\n");
		return;
	}

	sprintf(ptr1, "hello hello you are a buffalo\0");
	printf("String ptr1: %s\n", ptr1);

	ptr2 = (char *) memalloc(sizeof(char) * 600);
	if (!ptr2) {
		printf("Error in allocating ptr1\n");
		return;
	}

	sprintf(ptr2, "This is the way the world ends, not with a bang but a wimper. A quote by T.S. Eliot. Dun dun dun.................\0");
	printf("String ptr2: %s\n", ptr2);

	memfree(ptr1);
	memfree(ptr2);

	return 0;
}
