#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <assert.h>
#include <openssl/sha.h>

#define MAX_CACHE_SIZE	1024	/* number of elements */
#define HT_MAX_BUCKETS	128

/* Doubly Linked List Structure for LRU Cache */
struct lru_list {
	uint64_t address;
	void *data;
	size_t size;
	struct lru_list *next;
	struct lru_list *prev;
};

struct lru_hash {
	unsigned char key[SHA_DIGEST_LENGTH];
	struct lru_list *node;
	struct lru_hash *next;
};

struct lru_cache {
	uint64_t alloc_addr;
	int max_elements;
	int cur_elements;
	struct lru_list *head;
	int ht_max_buckets;
	struct lru_hash **hashtable;
};

struct lru_cache * lru_cache_initialize(int max_queue_size, int max_ht_buckets);
int lru_cache_destroy(struct lru_cache *cache);
struct lru_list * lru_cache_lookup(struct lru_cache *cache, uint64_t addr);
int lru_cache_insert(struct lru_cache *cache, uint64_t addr, void *data, int size);

