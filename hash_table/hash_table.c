/*
 * Copyright (c) 2013-2014 File systems and Storage Lab (FSL)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include "hash_table.h"

static struct hash_entry *hash_table_create_node(void *key, uint32_t ksize,
		void *value, uint32_t vsize)
{
	struct hash_entry *node = NULL;
	assert(key && value && ksize > 0 && vsize > 0);

	node = (struct hash_entry *) malloc(sizeof(struct hash_entry));
	if (!node) {
		fprintf(stderr, "Error in allocating hash entry.\n");
		goto out;
	}

	node->key = malloc(ksize);
	if (!node->key) {
		fprintf(stderr, "Error in allocating key.\n");
		goto out_free_node;
	}

	memcpy(node->key, key, ksize);

	node->value = malloc(vsize);
	if (!node->value) {
		fprintf(stderr, "Error in allocating value.\n");
		goto out_free_key;
	}

	memcpy(node->value, value, vsize);

	node->key_size = ksize;
	node->value_size = vsize;

	node->next = NULL;

	goto out;

out_free_key:
	free(node->key);
out_free_node:
	free(node);
	node = NULL;
out:
	return node;
}

static void hash_table_free_node(struct hash_entry *node)
{
	assert(node);

	node->next = NULL;

	if (node->key)
		free(node->key);
	if (node->value)
		free(node->value);

	free(node);
}

struct hash_table *hash_table_init(uint32_t num_buckets)
{
	struct hash_table *ht;
	assert (num_buckets > 0);

	ht = (struct hash_table *) malloc(sizeof(struct hash_table));
	if (!ht) {
		fprintf(stderr, "Error in allocating hash table.\n");
		goto out;
	}

	ht->htable = (struct hash_entry **) malloc(sizeof(struct hash_entry *)
			* num_buckets);
	if (!ht->htable) {
		fprintf(stderr, "Error in allocating hash entry array.\n");
		goto out_free_ht;
	}

	ht->num_buckets = num_buckets;

	goto out;

out_free_ht:
	free(ht);
	ht = NULL;
out:
	return ht;
}

void hash_table_destroy(struct hash_table *ht)
{
	int i = 0;
	struct hash_entry *tmp = NULL, *itr = NULL;

	assert(ht);

	for (i = 0; i < ht->num_buckets; i++) {
		if (!ht->htable[i])
			continue;

		itr = ht->htable[i];
		while (itr) {
			tmp = itr;
			itr = tmp->next;
			hash_table_free_node(tmp);
		}
	}

	free(ht);
}

static void hash_entry_list_add_node(struct hash_entry **head,
		struct hash_entry *node)
{
	assert(node);

	if (!(*head)) {
		*head = node;
		return;
	}

	node->next = *head;
	*head = node;

	return;
}

int hash_table_insert(struct hash_table *ht, void *key, uint32_t ksize,
		void *value, uint32_t vsize)
{
	int ret = 0, i;
	struct hash_entry *node = NULL;
	uint64_t hash = 0;
	uint32_t index = 0;

	assert(ht && key && value && ksize > 0 && vsize > 0);

	/* hash = hash * 31 + key[i] */
	for (i = 0; i < ksize; i++)
		hash = (hash << 5) - hash + ((char *)key)[i];

	index = hash % ht->num_buckets;

	node = hash_table_create_node(key, ksize, value, vsize);
	if (!node) {
		fprintf(stderr, "Error in creating hash entry node.\n");
		ret = -1;
		goto out;
	}

	/* Insert into hashtable now at head */
	hash_entry_list_add_node(&(ht->htable[index]), node);

out:
	return ret;
}

int hash_table_lookup(struct hash_table *ht, void *key, uint32_t ksize,
		void **value, uint32_t *vsize)
{
	int found = 0, i;
	struct hash_entry *itr = NULL;
	uint64_t hash = 0;
	uint32_t index = 0;

	assert(ht && key && ksize > 0);

	/* hash = hash * 31 + key[i] */
	for (i = 0; i < ksize; i++)
		hash = (hash << 5) - hash + ((char *)key)[i];

	index = hash % ht->num_buckets;

	if (!ht->htable[index])
		goto out;

	itr = ht->htable[index];
	while (itr) {
		if ((itr->key_size == ksize) &&
				(!memcmp(itr->key, key, ksize))) {
			*value = malloc(itr->value_size);
			if (!*value) {
				fprintf(stderr, "Malloc failed.\n");
				found = -1;
				goto out;
			}

			memcpy(*value, itr->value, itr->value_size);
			*vsize = itr->value_size;
			found = 1;
			break;
		}

		itr = itr->next;
	}

out:
	return found;
}

int main(int argc, char *argv[])
{
	struct hash_table *table = NULL;
	int *val;
	int ret, val_size, value;

	table = hash_table_init(5);
	if (!table) {
		printf("\nError! 1\n");
		return 1;
	}

	value = 2;
	hash_table_insert(table, "txt", 3, (void *)&value, 4);	
	value = 3;
	hash_table_insert(table, "doc", 3, (void *)&value, 4);	
	value = 1;
	hash_table_insert(table, "blah", 4, (void *)&value, 4);	
	value = 4;
	hash_table_insert(table, "c", 1, (void *)&value, 4);

	printf("\n********************************************************\n");
	ret = hash_table_lookup(table, "txt", 3, (void *)&val, &val_size);
	printf("\nRet: %d, Value: %d, val_size: %d\n", ret, *val, val_size);
	ret = hash_table_lookup(table, "doc", 3, (void *)&val, &val_size);
	printf("\nRet: %d, Value: %d, val_size: %d\n", ret, *val, val_size);
	ret = hash_table_lookup(table, "c", 1, (void *)&val, &val_size);
	printf("\nRet: %d, Value: %d, val_size: %d\n", ret, *val, val_size);
	ret = hash_table_lookup(table, "blah", 4, (void *)&val, &val_size);
	printf("\nRet: %d, Value: %d, val_size: %d\n", ret, *val, val_size);
	ret = hash_table_lookup(table, "cd", 2, (void *)&val, &val_size);
	printf("\nRet: %d, Value: %d, val_size: %d\n", ret, *val, val_size);
	value = 5;
	hash_table_insert(table, "cd", 2, (void *)&value, 4);
	ret = hash_table_lookup(table, "cd", 2, (void *)&val, &val_size);
	printf("\nRet: %d, Value: %d, val_size: %d\n", ret, *val, val_size);
	value = 8;
	hash_table_insert(table, "cd", 2, (void *)&value, 4);
	ret = hash_table_lookup(table, "cd", 2, (void *)&val, &val_size);
	printf("\nRet: %d, Value: %d, val_size: %d\n", ret, *val, val_size);
	printf("\n********************************************************\n");

	hash_table_destroy(table);

	return 0;
}
