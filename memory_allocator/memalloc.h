#ifndef MEMALLOC_H
#define MEMALLOC_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <inttypes.h>
#include <assert.h>

void * memalloc(size_t size);
void memfree(void * data);

#endif /* MEMALLOC_H */
