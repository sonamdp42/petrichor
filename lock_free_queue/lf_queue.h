/*
 * Copyright (c) 2013-2014 File systems and Storage Lab (FSL)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#ifndef IOQUEUE_H
#define IOQUEUE_H

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
#include <pthread.h>

#define CHUNK_TYPE_LEN	10
#define CHUNK_SIZE	4096
#define MAX_HASH_SIZE	256

struct lf_queue_node {
	void *chunk;
	uint64_t chunk_size;
	char chunk_type[CHUNK_TYPE_LEN + 1];
	unsigned char hash_key[MAX_HASH_SIZE];
	uint32_t hash_key_size;
	void *ptr;	/* For storing backend specific data */
	uint32_t ptr_size;
};

struct lf_queue {
	int max_elements;
	int cur_elements;
	int head;
	int tail;
	struct lf_queue_node **queue_array;
};

int lf_queue_is_empty(struct lf_queue *queue);
int lf_queue_is_full(struct lf_queue *queue);
struct lf_queue *lf_queue_init(int max_elements);
int lf_queue_destroy(struct lf_queue *queue);
struct lf_queue_node *lf_queue_alloc_node(void *data, uint64_t data_size,
                uint64_t actual_data_size, char *data_type,
                unsigned char *hash, uint32_t hash_size,
                void *ptr, uint32_t ptr_size);
void lf_queue_free_node(struct lf_queue_node **node);
int lf_queue_enqueue(struct lf_queue *queue, struct lf_queue_node *node);
struct lf_queue_node *lf_queue_dequeue(struct lf_queue *queue);

#endif /* IOQUEUE_H */
