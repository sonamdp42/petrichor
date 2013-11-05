/*
 * Copyright (c) 2013-2014 File systems and Storage Lab (FSL)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#ifndef HASH_TABLE_H
#define HASH_TABLE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <ctype.h>
#include <getopt.h>
#include <assert.h>
#include <dirent.h>
#include <malloc.h>

/* Chained hash table  */
struct hash_entry {
	uint32_t key_size;
	void *key;
	uint32_t value_size;
	void *value;
	struct hash_entry *next;
};

struct hash_table {
	uint32_t num_buckets;
	struct hash_entry **htable;
};

struct hash_table *hash_table_init(uint32_t num_buckets);
void hash_table_destroy(struct hash_table *ht);
int hash_table_insert(struct hash_table *ht, void *key, uint32_t ksize, void *value, uint32_t vsize);
int hash_table_lookup(struct hash_table *ht, void *key, uint32_t ksize, void **value, uint32_t *vsize);

#endif /* HASH_TABLE_H */
