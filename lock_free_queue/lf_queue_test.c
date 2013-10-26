#include <stdio.h>
#include <pthread.h>
#include <stdint.h>
#include <inttypes.h>

#include "lf_queue.h"

#define NUM_REQ 1000000

struct lf_queue *queue;

void* producer(void *arg)
{
	struct lf_queue_node *node;
	char data[4096];
	uint64_t i;

	for(i = 1; i < NUM_REQ; i++) {
		snprintf(data, 4095, "%" PRIu64, i);
		node = lf_queue_alloc_node((void *)data, strlen(data), 4096, "doc", (unsigned char *) "hash", 4, NULL, 0);
		lf_queue_enqueue(queue, node);

		if (!(i % 5000)) {
			sleep(1);
		}
	}

	return NULL;
}

void* consumer(void *arg)
{
	struct lf_queue_node *node;
	uint64_t i;

	for(i = 1; i < NUM_REQ; i++) {
		node = lf_queue_dequeue(queue);
		fprintf(stdout, "%s\n", (char *) node->chunk);
		lf_queue_free_node(&node);

	}

	return NULL;
}

int main(int argc, char *argv[])
{
	pthread_t t1, t2;

	queue = lf_queue_init(NUM_REQ / 10);

	pthread_create(&t1, NULL, producer, (void*)NULL);
	pthread_create(&t2, NULL, consumer, (void*)NULL);

	pthread_join(t1, NULL);
	pthread_join(t2, NULL);

	return 0;
}
