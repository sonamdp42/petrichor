#include "lru.h"

/***********************************************************************************
 *										   *
 *				  LRU LIST FUNCTIONS 				   *
 *				  						   *
 ***********************************************************************************/

/* Creates an LRU Cache node */
static struct lru_list *create_lru_node(uint64_t addr, void *data, size_t size)
{
	struct lru_list *node = NULL;

	if (!data || !size) {
		printf("\nData sent to add to LRU Cache is NULL or 0 size. Exiting...\n");
		return NULL;
	}

	node = (struct lru_list *) malloc(sizeof(struct lru_list));
	if (!node) {
		printf("\nError: cannot malloc lru list node. Exiting...\n");
		return NULL;
	}

	node->data = malloc(size);
	if (!node->data) {
		printf("\nError: cannot malloc lru list data. Exiting...\n");
		return NULL;
	}

	memcpy(node->data, data, size);

	node->size = size;
	node->next = NULL;
	node->prev = NULL;
	node->address = addr;

	return node;
}

/* Free an LRU Cache node */
static int free_lru_node(struct lru_list **node)
{
	if (!*node) {
		printf("\nThe LRU node is NULL, cannot free, Exiting...\n");
		return -1;
	}

	if ((*node)->data) {
		free((*node)->data);
		(*node)->data = NULL;
	}

	free(*node);
	*node = NULL;

	return 0;
}

/* Insert node to Front of LRU Cache */
static struct lru_list * insert_new_lru_node(struct lru_cache *cache, uint64_t addr, void *data, size_t size)
{
	int ret = 0;
	struct lru_list *node = NULL, *tmp = NULL;

	assert(cache && data && size);

	/* LRU List is empty */
	node = create_lru_node(addr, data, size);
	if (!cache->head) {
		cache->head = (struct lru_list *)malloc(sizeof(struct lru_list));
		cache->head->data = NULL;
		cache->head->size = 0;
		cache->head->prev = NULL;
	} else if (!cache->head->next) { /* Maybe all deleted? */
		/* Do nothing */
	} else { /* At least some elements in LRU cache */
		tmp = cache->head->next;
		node->next = tmp;
		if (tmp->prev)
			node->prev = tmp->prev;
		else
			node->prev = tmp; /* Just two nodes */
		node->prev->next = node;
		tmp->prev = node;
	}
	cache->head->next = node;

	cache->cur_elements++;

out:
	return node;
}

/* Move existing node to Front of LRU Cache */
static int move_lru_node(struct lru_cache *cache, struct lru_list **node)
{
	int ret = 0;
	struct lru_list *tmp = NULL, *tmp2 = NULL;

	assert(cache && cache->head && cache->head->next && *node);

	printf("move lru node\n");

	if (!(*node)->next && !(*node)->prev) {
		/* Only element, don't need to move it */
		goto out;
	} else if (!(*node)->next || !(*node)->prev) {
		printf("\nMalformed node, Exiting...\n");
		ret = -1;
		goto out;
	}

	tmp2 = *node;
	(*node)->prev->next = tmp2->next;
	tmp2->next->prev = tmp2->prev;
	tmp2->next = NULL;
	tmp2->prev = NULL;

	tmp = cache->head->next;
	tmp2->next = tmp;
	tmp2->prev = tmp->prev;
	tmp2->prev->next = tmp2;
	tmp->prev = tmp2;
	cache->head->next = tmp2;

out:
	return ret;
}

/* We always delete the last element in LRU Cache */
static uint64_t delete_lru_node(struct lru_cache *cache)
{
	int ret = 0;
	uint64_t addr = 0;
	struct lru_list *tmp = NULL, *tmp1 = NULL;

	assert(cache && cache->head && cache->head->next);

	if (cache->cur_elements < 1) {
		/* TODO: Just return? Cannot delete an element... */
		printf("\nLRU cache is empty, cannot delete!\n");
		ret = -1;
		goto out;
	}

	tmp = cache->head->next;

	if (!tmp->next && !tmp->prev) {
		cache->head->next = NULL;
		addr = tmp->address;
		ret = free_lru_node(&tmp);
		goto out;
	} else if (!tmp->next || !tmp->prev) {
		printf("\nMalformed node, Exiting...\n");
		ret = -1;
		goto out;
	}

	/* Special case for only two nodes: */
	if (tmp->next == tmp->prev) {
		tmp1 = tmp->next;
		tmp->next = NULL;
		tmp->prev = NULL;
		tmp1->next = NULL;
		tmp1->prev = NULL;
		addr = tmp1->address;
		ret = free_lru_node(&tmp1);
		goto out;
	}

	tmp = cache->head->next->prev;

	tmp->prev->next = tmp->next;
	tmp->next->prev = tmp->prev;
	tmp->next = NULL;
	tmp->prev = NULL;
	addr = tmp->address;
	ret = free_lru_node(&tmp);

out:
	if (ret < 0)
		return 0;
	else
		return addr;
}

static int destroy_lru_queue(struct lru_cache *cache)
{
	int ret = 0;

	assert(cache && cache->head && cache->head->next);

	while (cache->head->next) {
		ret = delete_lru_node(cache);
		if (!ret) {
			fprintf(stderr, "Error in deletig node from queue.\n");
			goto out;
		}
	}

out:
	if (!ret)
		return -1;
	else
		return 0;
}

/* Iterator function for LRU Cache */
int iterate_lru_list(struct lru_cache *cache)
{
	int count = 0;
	struct lru_list *tail = NULL, *itr = NULL;

	assert(cache && cache->head && cache->head->next);

	tail = itr = cache->head->next;

	do {
		printf("\n\nData for node %d: %s\n\n", count, (char *)itr->data);
		itr = itr->next;
		count++;
	} while (itr && tail != itr);

	if (itr && itr->data)
		printf("\n\nFor debugging: data at head node: %s, address: %"
				PRIu64 "\n\n", (char *)itr->data,
				itr->address);

	return 0;
}

/***********************************************************************************
 *										   *
 *				  LRU HASH FUNCTIONS 				   *
 *				  						   *
 ***********************************************************************************/

static struct lru_hash *create_lru_hash_node(unsigned char *key, uint32_t key_len, struct lru_list *node)
{
	struct lru_hash *entry = NULL;

	assert (key && node && key_len == SHA_DIGEST_LENGTH);

	entry = (struct lru_hash *) malloc(sizeof(struct lru_hash));
	if (!entry) {
		fprintf(stderr, "Error in allocating hash entry.\n");
		return NULL;
	}

	memset(entry->key, 0, SHA_DIGEST_LENGTH);
	memcpy(entry->key, key, key_len);
	entry->node = node;
	entry->next = NULL;

	return entry;
}

static void free_lru_hash_node(struct lru_hash **entry)
{
	assert(entry && *entry);

	(*entry)->node = NULL;
	(*entry)->next = NULL;
	free(*entry);
}

/* This will overwrite existing entry, or create new entry. */
static int insert_lru_hash_node(struct lru_cache *cache, struct lru_list *node)
{
	int ret = 0;
	uint32_t index, ht_index;
	unsigned char hashbuf[SHA_DIGEST_LENGTH];
	struct lru_hash *entry = NULL, *itr = NULL;
	unsigned char addrbuf[26];

	assert(cache && node);

	snprintf(addrbuf, 25, "%" PRIu64, node->address);
	SHA1(addrbuf, strlen(addrbuf), hashbuf);
	memcpy(&index, hashbuf, 4);
	ht_index = index % cache->ht_max_buckets;
	entry = cache->hashtable[ht_index];

	/* Nothing ever entered for this index! */
	if (!entry) {
		cache->hashtable[ht_index] = create_lru_hash_node(hashbuf,
				SHA_DIGEST_LENGTH, node);
		if (!cache->hashtable[ht_index]) {
			fprintf(stderr, "Error in creating initial entry for index %u", ht_index);
			ret = -1;
		}

		goto out;
	}

	itr = entry;
	do {
		if (!memcmp(itr->key, hashbuf, SHA_DIGEST_LENGTH)) {
			/* Just update the node. */
			itr->node = node;
			goto out;
		}

		if (!itr->next)
			break;
		else
			itr = itr->next;
	} while (itr->next);

	/* Insert new node in chain. */
	itr->next = create_lru_hash_node(hashbuf, SHA_DIGEST_LENGTH, node);
	if (!itr->next) {
		fprintf(stderr, "Error in creating new node in chain for index %u", ht_index);
		ret = -1;
	}
out:
	return ret;
}

static struct lru_list *lookup_lru_hash_node(struct lru_cache *cache, uint64_t addr)
{
	int found = 0;
	uint32_t index, ht_index;
	unsigned char hashbuf[SHA_DIGEST_LENGTH];
	struct lru_hash *entry = NULL, *itr = NULL;
	unsigned char addrbuf[26];
	struct lru_list *node = NULL;

	assert(cache);

	snprintf(addrbuf, 25, "%" PRIu64, addr);
	SHA1(addrbuf, strlen(addrbuf), hashbuf);
	memcpy(&index, hashbuf, 4);
	ht_index = index % cache->ht_max_buckets;
	entry = cache->hashtable[ht_index];

	if (!entry)
		goto out;

	itr = entry;
	while (itr) {
		if (!memcmp(itr->key, hashbuf, SHA_DIGEST_LENGTH)) {
			found = 1;
			node = itr->node;
			goto out;
		}

		itr = itr->next;
	}

out:
	return node;
}

static int delete_lru_hash_node(struct lru_cache *cache, uint64_t addr)
{
	int ret = 0;
	uint32_t index, ht_index;
	unsigned char hashbuf[SHA_DIGEST_LENGTH];
	struct lru_hash *entry = NULL, *itr = NULL, *prev = NULL;
	unsigned char addrbuf[26];

	assert(cache);

	snprintf(addrbuf, 25, "%" PRIu64, addr);
	SHA1(addrbuf, strlen(addrbuf), hashbuf);
	memcpy(&index, hashbuf, 4);
	ht_index = index % cache->ht_max_buckets;
	entry = cache->hashtable[ht_index];

	if (!entry) {
		fprintf(stderr, "Entry is null, error!.\n");
		ret = -1;
		goto out;
	}

	itr = entry;
	while(itr) {
		if (!memcmp(itr->key, hashbuf, SHA_DIGEST_LENGTH)) {
			if (!prev) {
				/* First node in this list. */
				cache->hashtable[ht_index] = itr->next;
				free_lru_hash_node(&itr);
				goto out;
			}

			prev->next = itr->next;
			free_lru_hash_node(&itr);
			goto out;
		}

		prev = itr;
		itr = itr->next;
	}

	fprintf(stderr, "Element to delete not found!\n");
	ret = -1;
out:
	return ret;
}

static int destroy_lru_hashtable(struct lru_cache *cache)
{
	int ret = 0, i;
	struct lru_hash *itr = NULL, *tmp = NULL;

	assert(cache && cache->hashtable);

	for (i = 0; i < cache->ht_max_buckets; i++) {
		if (!cache->hashtable[i])
			continue;

		itr = cache->hashtable[i];
		while (itr) {
			tmp = itr;
			itr = itr->next;
			free_lru_hash_node(&tmp);
		}
	}

	return ret;
}

/***********************************************************************************
 *										   *
 *				  LRU CACHE FUNCTIONS 				   *
 *				  						   *
 ***********************************************************************************/

struct lru_list * lru_cache_lookup(struct lru_cache *cache, uint64_t addr)
{
	int ret = 0;
	struct lru_list *node = NULL;

	assert(cache && addr > 0);

	node = lookup_lru_hash_node(cache, addr);
	if (node) {
		/* Need to move to front of list */
		printf("going to move node to front\n");
		ret = move_lru_node(cache, &node);
		if (ret) {
			fprintf(stderr, "Moving LRU node to front failed!\n");
			node = NULL;
		}
	}

	return node;
}

int lru_cache_insert(struct lru_cache *cache, uint64_t addr, void *data, int size)
{
	int ret = 0;
	struct lru_list *node = NULL;

	assert(cache && data && addr > 0);

	/* What if the LRU Cache is full? Delete an item and then add... */
	if (cache->cur_elements >= cache->max_elements) {
		ret = delete_lru_node(cache);
		if (!ret) {
			fprintf(stderr, "Error in trying to free up space.\n");
			ret = -1;
			goto out;
		}

		ret = delete_lru_hash_node(cache, ret);
		if (ret) {
			fprintf(stderr, "Error in freeing node in hash table.\n");
			ret = -1;
			goto out;
		}
	}

	node = insert_new_lru_node(cache, addr, data, size);
	if (!node) {
		fprintf(stderr, "Error in inserting node to list.\n");
		ret = -1;
		goto out;
	}

	ret = insert_lru_hash_node(cache, node);
	if (ret) {
		fprintf(stderr, "Error in inserting node to hash.\n");
		ret = -1;
		goto out;
	}

out:
	return ret;
}

struct lru_cache * lru_cache_initialize(int max_queue_size, int max_ht_buckets)
{
	struct lru_cache *cache = NULL;

	assert(max_queue_size > 0 && max_ht_buckets > 0 && max_queue_size <=
			MAX_CACHE_SIZE && max_ht_buckets <= HT_MAX_BUCKETS);

	cache = (struct lru_cache *) malloc(sizeof(struct lru_cache));
	if (!cache) {
		fprintf(stderr, "Failed to allocate lru_cache.\n");
		return NULL;
	}

	cache->max_elements = max_queue_size;

	cache->hashtable = (struct lru_hash **) malloc(sizeof(struct lru_hash
				*) * max_ht_buckets);
	if (!cache->hashtable) {
		fprintf(stderr, "Failed to allocate hashtable.\n");
		goto out_cache;
	}

	cache->ht_max_buckets = max_ht_buckets;
	cache->cur_elements = 0;
	/* Setting to NULL, first insertion takes care of allocating */
	cache->head = NULL;

	goto out;

out_cache:
	free(cache);
	cache = NULL;
out:
	return cache;
}

int lru_cache_destroy(struct lru_cache *cache)
{
	int ret = 0;

	/* Destroy hashtable */
	ret = destroy_lru_hashtable(cache);

	/* Destroy doubly linked-list */
	ret = destroy_lru_queue(cache);

	free(cache);
	cache = NULL;

	return ret;
}

int main(int argc, char *argv[])
{
	int ret = 0, option = 0;
	struct lru_list *node = NULL;
	char buf[129];

	unsigned int queue_size;
	unsigned int ht_size;
	struct lru_cache *cache;
	uint64_t addr;

	printf("\nEnter the queue size: ");
	scanf("%u", &queue_size);

	printf("\nEnter the hash table size: ");
	scanf("%u", &ht_size);

	cache = lru_cache_initialize(queue_size, ht_size);
	if (!cache) {
		fprintf(stderr, "Error initializing the cache!.\n");
		ret = -1;
		goto out;
	}

	while(1) {
		printf("\n\nEnter option \n1: insert element, \n2: address"
				"lookup/insert if missing, \n3: address lookup,"
				"\n4: dump list, \n5: quit\n");
		scanf("%d", &option);

		switch(option) {
		case 1:
			printf("\nEnter data: ");
			fgets(buf, 128, stdin);
			printf("\nEnter address: ");
			scanf("%" PRIu64, &addr);
			ret = lru_cache_insert(cache, addr, (void *)buf, strlen(buf));
			if (ret) {
				fprintf(stderr, "Error in inserting to cache.\n");
				goto out;
			}
			break;
		case 2:
			printf("\nEnter address to lookup: ");
			scanf("%" PRIu64, &addr);
			node = lru_cache_lookup(cache, addr);
			if (!node) {
				printf("\nNode not found. Enter data to store \
						at addr %" PRIu64 ": ", addr);
				fgets(buf, 128, stdin);
				ret = lru_cache_insert(cache, addr, (void *)buf, strlen(buf));
				if (ret) {
					fprintf(stderr, "Error in inserting to cache.\n");
					goto out;
				}
			} else
				printf("\nNode found, data: %s", (char *)node->data);
			break;
		case 3:
			printf("\nEnter address to lookup: ");
			scanf("%" PRIu64, &addr);
			node = lru_cache_lookup(cache, addr);
			if (!node)
				printf("\nNode not found.");
			else
				printf("\nNode found, data: %s", (char *)node->data);
			break;
		case 4:
			iterate_lru_list(cache);
			break;
		case 5:
			printf("\nQuitting!");
			goto out;
			break;
		default:
			printf("\nInvalie option entered, try again!");
			break;
		}
	}

out:
	if (cache) {
		lru_cache_destroy(cache);
		cache = NULL;
	}
	return ret;
}
