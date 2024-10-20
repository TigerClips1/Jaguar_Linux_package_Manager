/* common.c -  PS4linux package manager (PS4)
 *
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "ps4_defines.h"

const struct ps4_array _ps4_array_empty = { .num = 0 };

void *_ps4_array_resize(const struct ps4_array *array, size_t item_size, size_t num, size_t cap)
{
	uint32_t old_num;
	struct ps4_array *tmp;

	if (cap == 0) {
		_ps4_array_free(array);
		return (void*) &_ps4_array_empty;
	}
	if (num > cap) num = cap;
	old_num = array->num;

	if (!array->allocated) array = NULL;
	tmp = realloc((void *) array, sizeof(struct ps4_array) + cap * item_size);
	*tmp = (struct ps4_array) {
		.num = num,
		.capacity = cap,
		.allocated = 1,
	};
	if (unlikely(old_num < num)) memset(((void*)(tmp+1)) + item_size * old_num, 0, item_size * (num - old_num));
	return tmp;
}

void *_ps4_array_copy(const struct ps4_array *array, size_t item_size)
{
	struct ps4_array *copy = _ps4_array_resize(&_ps4_array_empty, item_size, 0, array->num);
	if (array->num != 0) {
		memcpy(copy+1, array+1, item_size * array->num);
		copy->num = array->num;
	}
	return copy;
}

void *_ps4_array_grow(const struct ps4_array *array, size_t item_size)
{
	return _ps4_array_resize(array, item_size, array->num, array->capacity + min(array->capacity + 2, 64));
}

void _ps4_array__free(const struct ps4_array *array)
{
	free((void*) array);
}

time_t ps4_get_build_time(void)
{
	static int initialized = 0;
	static time_t timestamp = 0;
	char *source_date_epoch;

	if (initialized) return timestamp;
	source_date_epoch = getenv("SOURCE_DATE_EPOCH");
	if (source_date_epoch && *source_date_epoch)
		timestamp = strtoull(source_date_epoch, NULL, 10);
	else	timestamp = time(NULL);
	initialized = 1;
	return timestamp;
}
