/*
 * Copyright (c) 2013-2014 File systems and Storage Lab (FSL)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include "lf_queue.h"

int lf_queue_is_empty(struct lf_queue *queue)
{
	assert (queue);
	assert (queue->cur_elements >= 0);

	if (!queue->cur_elements)
		return 1;
	return 0;
}

int lf_queue_is_full(struct lf_queue *queue)
{
	assert (queue);
	assert (queue->cur_elements <= queue->max_elements);

	if (queue->cur_elements == queue->max_elements)
		return 1;
	return 0;
}

/* TODO: Remove this, only required for debugging */
static void lf_queue_dump(struct lf_queue *queue)
{
	int count = 0;

	assert(queue);

	printf("\ncur elements: %d, count: %d\n", queue->cur_elements, count);

	while (count < queue->cur_elements) {
		printf("%dth element: %s\n", count,
			(char *)queue->queue_array[(queue->head + count) % (queue->max_elements)]->chunk);
		count++;
	}
}

struct lf_queue_node *lf_queue_alloc_node(void *data, uint64_t data_size,
		uint64_t actual_data_size, char *data_type,
		unsigned char *hash, uint32_t hash_size,
		void *ptr, uint32_t ptr_size)
{
	struct lf_queue_node *node = NULL;

	assert(data && data_type && data_size <= CHUNK_SIZE && data_size > 0
			&& hash && strlen(data_type) <= CHUNK_TYPE_LEN &&
			hash_size > 0 && hash_size <= MAX_HASH_SIZE);

	node = (struct lf_queue_node *) malloc(sizeof(struct lf_queue_node));
	if (!node) {
		fprintf(stderr, "Error in mallocing io queue node\n");
		goto out;
	}

	node->chunk = malloc(CHUNK_SIZE * sizeof(char));
	if (!node->chunk) {
		fprintf(stderr, "Error in mallocing io queue node data\n");
		goto out_alloc_node;
	}

	memset(node->chunk, 0, CHUNK_SIZE);
	memcpy(node->chunk, data, data_size);

	memset(node->chunk_type, 0, CHUNK_TYPE_LEN);
	strncpy(node->chunk_type, data_type, strlen(data_type));
	node->chunk_type[strlen(data_type)] = '\0';

	node->chunk_size = actual_data_size;

	memset(node->hash_key, 0, MAX_HASH_SIZE);
	memcpy(node->hash_key, hash, hash_size);

	if (ptr && ptr_size > 0) {
		/* Copying over the pointer data */
		ptr = malloc(ptr_size);
		if (!ptr) {
			fprintf(stderr, "Error in allocating the void ptr\n");
			goto out_alloc_node_data;
		}

		memset(node->ptr, 0, ptr_size);
		memcpy(node->ptr, ptr, ptr_size);
		node->ptr_size = ptr_size;
	} else {
		node->ptr = NULL;
		node->ptr_size = 0;
	}

	goto out;

out_alloc_node_data:
	free(node->chunk);
	node->chunk = NULL;
out_alloc_node:
	free(node);
	node = NULL;
out:
	return node;
}

void lf_queue_free_node(struct lf_queue_node **node)
{
	assert(*node);

	if ((*node)->ptr) {
		free((*node)->ptr);
		(*node)->ptr = NULL;
	}

	if ((*node)->chunk) {
		free((*node)->chunk);
		(*node)->chunk = NULL;
	}

	free(*node);
	*node = NULL;

	return;
}

int lf_queue_enqueue(struct lf_queue *queue, struct lf_queue_node *node)
{
	int ret = 0;
	assert(queue && node);
	assert(queue->cur_elements <= queue->max_elements);

	while (queue->cur_elements == queue->max_elements) {
		/* Cannot add more elements, queue full */
		usleep(10);
	}

	assert(queue->tail >= 0 && queue->tail < queue->max_elements);
	queue->queue_array[queue->tail] = node;

	queue->tail = (queue->tail + 1) % (queue->max_elements);

	__sync_fetch_and_add(&(queue->cur_elements), 1); 

	return ret;
}

struct lf_queue_node *lf_queue_dequeue(struct lf_queue *queue)
{
	struct lf_queue_node *node = NULL;

	assert(queue);
	assert(queue->cur_elements >= 0);

	while (!queue->cur_elements) {
		/* Cannot dequeue elements, queue empty */
		usleep(10);
	}

	assert(queue->head >= 0 && queue->head < queue->max_elements);
	node = queue->queue_array[queue->head];
	assert(node); /* To check for errors */
	queue->queue_array[queue->head] = NULL;

	queue->head = (queue->head + 1) % (queue->max_elements);

	__sync_fetch_and_sub(&(queue->cur_elements), 1); 

	return node;
}

struct lf_queue *lf_queue_init(int max_elements)
{
	struct lf_queue *queue = NULL;
	assert(max_elements > 0);

	queue = (struct lf_queue *)malloc(sizeof(struct lf_queue));
	if (!queue) {
		fprintf(stderr, "Unable to allocate memory for io queue.\n");
		goto out;
	}

	queue->queue_array = (struct lf_queue_node **)malloc(
			sizeof(struct lf_queue_node *) * max_elements);
	if (!queue->queue_array) {
		fprintf(stderr, "Allocating queue_array failed.\n");
		goto out_queue;
	}

	queue->max_elements = max_elements;
	queue->cur_elements = 0;
	queue->head = 0;
	queue->tail = 0;

	goto out;

out_queue:
	free(queue);
	queue = NULL;
out:
	return queue;
}

/* Returns number of elements that were freed, if any. */
int lf_queue_destroy(struct lf_queue *queue)
{
	int count_freed = 0;
	
	assert(queue);

	while (queue->cur_elements > 0) {
		lf_queue_free_node(&queue->queue_array[queue->head]);
		if (queue->head + 1 > queue->max_elements - 1)
			queue->head = (queue->head + 1) %
					(queue->max_elements);
		else
			queue->head++;

		queue->cur_elements--;
		count_freed++;
	}

	free(queue);

	return count_freed;
}
