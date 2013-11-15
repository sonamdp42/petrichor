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

void * memalloc_head = NULL;
void * memalloc_start = NULL;

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
	void *prev = NULL, *next = NULL, *ret = NULL;
	size_t min_mem = sizeof(size_t) + sizeof(uint32_t) + sizeof(uint32_t);

	//printf("Enter: %s\n", __FUNCTION__);
	printf("Enter: %s, magic: %u, MAGIC: %u\n", __FUNCTION__, magic, MAGIC);
	assert(size > 0);

	aligned_size = closest_multiple_of_min_block(size);

	printf("aligned size: %lu, size: %lu\n", aligned_size, size);

	/* First check if memalloc_head is NULL */
	if (!memalloc_head || !memalloc_start) {
		printf("First element added, calling sbrk()\n");

		if (aligned_size >= INCREMENT_LEN)
			to_allocate = aligned_size + INCREMENT_LEN;
		else
			to_allocate = INCREMENT_LEN;

		memalloc_start = sbrk(to_allocate);
		if (memalloc_start == (void *) -1) {
			fprintf(stderr, "Error in sbrk(): %s, %d\n", strerror(errno), errno);
			return NULL;
		}

		memcpy(memalloc_start, &aligned_size, sizeof(size_t));
		memcpy(memalloc_start + sizeof(size_t), &magic, sizeof(uint32_t));
		memcpy(memalloc_start + sizeof(size_t) + sizeof(uint32_t) + aligned_size, &magic, sizeof(uint32_t));

		size_t verifylen = 0;
		memcpy(&verifylen, memalloc_start, sizeof(size_t));
		printf("verified lem: %lu\n", verifylen);

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
		printf("Iterating....\n");

		if (itr->size - min_mem >= aligned_size) {
			free_size = itr->size;
			prev = itr->prev;
			next = itr->next;

			printf("free size: %lu\n", free_size);

			ret = itr;

			if (aligned_size < itr->size - 2 * min_mem - MIN_BLOCK_SIZE) {
				printf("We have enough space for a free slot here.\n");
				/* We have enough space for a free slot here. */
				itr = itr + aligned_size + min_mem;

				/* Update previous free slot's next pointer */
				if (prev) {
					printf("Prev exists\n");
					memcpy(&flist, prev, sizeof(struct free_list));
					flist.next = itr;
					memcpy(prev, &flist, sizeof(struct free_list));
				}

				/* Update next free slot's prev pointer */
				if (next) {
					printf("Next exists\n");
					memcpy(&flist, next, sizeof(struct free_list));
					flist.prev = itr;
					memcpy(next, &flist, sizeof(struct free_list));
				}

				/* Add entry for this free slot */
				printf("Memcpy not done!\n");
				flist.size = free_size - aligned_size - min_mem;
				flist.prev = prev;
				flist.next = next;
				printf("Memcpy not done 2! %u\n", flist.size);
				memcpy(itr, &flist, sizeof(struct free_list));
				printf("Memcpy done!\n");
			} else {
				printf("We do not have enough space for a free slot here.\n");
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
				if (itr == memalloc_head)
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

	printf("Exit: %s\n", __FUNCTION__);
	return ret + min_mem - sizeof(uint32_t);
}

void memfree(void * data)
{
	size_t length;
	uint32_t magic = MAGIC;
	struct free_list *freeList = NULL, *itr = NULL, *prev = NULL, *next = NULL, flist;

	printf("Enter: %s, magic: %u, MAGIC: %u\n", __FUNCTION__, magic, MAGIC);

	assert(data);

	memcpy(&length, data - sizeof(size_t) - sizeof(uint32_t), sizeof(size_t));
	assert(length > 0);

	printf("length obtained: %lu\n", length);

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
		printf("Only one entry in free list\n");
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
		flist.next = data;
		memcpy(prev, &flist, sizeof(struct free_list));
	}

	if (next) {
		memcpy(&flist, next, sizeof(struct free_list));
		flist.prev = data;
		memcpy(next, &flist, sizeof(struct free_list));
	}

	flist.size = length;
	flist.next = next;
	flist.prev = prev;
	memcpy(data - sizeof(size_t) - sizeof(uint32_t), &flist, sizeof(struct free_list));

	printf("Exit: %s\n", __FUNCTION__);
	return;
}

int main(int argc, char *argv[])
{
	char *ptr1 = NULL, *ptr2 = NULL;

	printf("sizeof char: %lu, sizeof int: %lu, sizeof size_t: %lu\n", sizeof(char), sizeof(int), sizeof(size_t));

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

	sprintf(ptr2, "In dire need of a haircut, oh no, oh no, oh no, blah blah blah blah blah, blue blue blue blue blue blue blue\0");
	printf("String ptr2: %s\n", ptr2);

	memfree(ptr1);
	memfree(ptr2);

	return 0;
}
