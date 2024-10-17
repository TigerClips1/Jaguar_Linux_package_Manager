/* ps4_defines.c - PS4linux package manager (PS4)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef PS4_DEFINES_H
#define PS4_DEFINES_H

#include <assert.h>
#include <endian.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#define ARRAY_SIZE(x)	(sizeof(x) / sizeof((x)[0]))
#define BIT(x)		(1U << (x))
#define min(a, b)	((a) < (b) ? (a) : (b))
#define max(a, b)	((a) > (b) ? (a) : (b))

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifndef NULL
#define NULL 0L
#endif

enum {
	PS4E_FIRST_VALUE = 1024,
	PS4E_EOF = PS4E_FIRST_VALUE,
	PS4E_DNS,
	PS4E_URL_FORMAT,
	PS4E_CRYPTO_ERROR,
	PS4E_CRYPTO_NOT_SUPPORTED,
	PS4E_CRYPTO_KEY_FORMAT,
	PS4E_SIGNATURE_GEN_FAILURE,
	PS4E_SIGNATURE_UNTRUSTED,
	PS4E_SIGNATURE_INVALID,
	PS4E_FORMAT_INVALID,
	PS4E_FORMAT_NOT_SUPPORTED,
	PS4E_PKGNAME_FORMAT,
	PS4E_PKGVERSION_FORMAT,
	PS4E_DEPENDENCY_FORMAT,
	PS4E_ADB_COMPRESSION,
	PS4E_ADB_HEADER,
	PS4E_ADB_VERSION,
	PS4E_ADB_SCHEMA,
	PS4E_ADB_BLOCK,
	PS4E_ADB_SIGNATURE,
	PS4E_ADB_INTEGRITY,
	PS4E_ADB_NO_FROMSTRING,
	PS4E_ADB_LIMIT,
	PS4E_ADB_PACKAGE_FORMAT,
	PS4E_V2DB_FORMAT,
	PS4E_V2PKG_FORMAT,
	PS4E_V2PKG_INTEGRITY,
	PS4E_V2NDX_FORMAT,
	PS4E_PACKAGE_NOT_FOUND,
	PS4E_INDEX_STALE,
	PS4E_FILE_INTEGRITY,
	PS4E_CACHE_NOT_AVAILABLE,
	PS4E_UVOL_NOT_AVAILABLE,
	PS4E_UVOL_ERROR,
	PS4E_UVOL_ROOT,
	PS4E_REMOTE_IO,
};

static inline void *ERR_PTR(long error) { return (void*) error; }
static inline void *ERR_CAST(const void *ptr) { return (void*) ptr; }
static inline int PTR_ERR(const void *ptr) { return (int)(long) ptr; }
static inline int IS_ERR(const void *ptr) { return (unsigned long)ptr >= (unsigned long)-4095; }

#if defined __GNUC__ && __GNUC__ == 2 && __GNUC_MINOR__ < 96
#define __builtin_expect(x, expected_value) (x)
#endif

#ifndef likely
#define likely(x) __builtin_expect((!!(x)),1)
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect((!!(x)),0)
#endif

#ifndef typeof
#define typeof(x) __typeof__(x)
#endif

#ifndef alignof
#define alignof(x) _Alignof(x)
#endif

#ifndef container_of
#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type,member) );})
#endif

#define ROUND_DOWN(x,a)		((x) & ~(a-1))
#define ROUND_UP(x,a)		(((x)+(a)-1) & ~((a)-1))

/* default architecture for PS4 packages. */
#if defined(__x86_64__)
#define ps4_DEFAULT_BASE_ARCH        "x86_64"
#else
#error PS4_DEFAULT_BASE_ARCH not detected for this architecture
#endif

#ifndef PS4_ARCH_PREFIX
#define PS4_DEFAULT_ARCH	PS4_DEFAULT_BASE_ARCH
#else
#define PS4_DEFAULT_ARCH	PS4_ARCH_PREFIX "-" PS4_DEFAULT_BASE_ARCH
#endif

#define PS4_MAX_REPOS		32	/* see struct ps4_package */
#define PS4_MAX_TAGS		16	/* see solver; unsigned short */
#define PS4_CACHE_CSUM_BYTES	4

static inline size_t ps4_calc_installed_size(size_t size)
{
	const size_t bsize = 4 * 1024;

	return (size + bsize - 1) & ~(bsize - 1);
}
static inline size_t muldiv(size_t a, size_t b, size_t c)
{
	unsigned long long tmp;
	tmp = a;
	tmp *= b;
	tmp /= c;
	return (size_t) tmp;
}
static inline size_t mulmod(size_t a, size_t b, size_t c)
{
	unsigned long long tmp;
	tmp = a;
	tmp *= b;
	tmp %= c;
	return (size_t) tmp;
}

static inline uint32_t get_unaligned32(const void *ptr)
{
#if defined(__x86_64__) || defined(__i386__)
	return *(const uint32_t *)ptr;
#else
	const uint8_t *p = ptr;
	return p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
#endif
}

typedef void (*ps4_progress_cb)(void *cb_ctx, size_t);

time_t ps4_get_build_time(void);

struct ps4_array {
	uint32_t num;
	uint32_t capacity : 31;
	uint32_t allocated : 1;
};

extern const struct ps4_array _ps4_array_empty;

void *_ps4_array_resize(const struct ps4_array *hdr, size_t item_size, size_t num, size_t cap);
void *_ps4_array_copy(const struct ps4_array *hdr, size_t item_size);
void *_ps4_array_grow(const struct ps4_array *hdr, size_t item_size);
void _ps4_array__free(const struct ps4_array *hdr);

static inline uint32_t _ps4_array_len(const struct ps4_array *hdr) { return hdr->num; }
static inline void _ps4_array_free(const struct ps4_array *hdr) {
	if (hdr->allocated) _ps4_array__free(hdr);
}
static inline struct ps4_array *_ps4_array_truncate(struct ps4_array *hdr, size_t num) {
	assert(num <= hdr->num);
	if (hdr->num != num) hdr->num = num;
	return hdr;
}

#define ps4_array_len(array)		_ps4_array_len(&(array)->hdr)
#define ps4_array_truncate(array, num)	_ps4_array_truncate(&(array)->hdr, num)
#define ps4_array_reset(array)		(typeof(array))((array)->hdr.allocated ? ps4_array_truncate(array, 0) : &_ps4_array_empty)
#define ps4_array_item_size(array)	sizeof((array)->item[0])
#define ps4_array_qsort(array, compare)	qsort((array)->item, (array)->hdr.num, ps4_array_item_size(array), compare)

#define ps4_ARRAY(array_type_name, item_type_name)			\
	struct array_type_name {					\
		struct ps4_array hdr;					\
		item_type_name item[];					\
	};								\
	static inline void						\
	array_type_name##_init(struct array_type_name **a) {		\
		*a = (void *) &_ps4_array_empty;			\
	}								\
	static inline void						\
	array_type_name##_free(struct array_type_name **a) {		\
		_ps4_array_free(&(*a)->hdr);				\
		*a = (void *) &_ps4_array_empty;			\
	}								\
	static inline void						\
	array_type_name##_resize(struct array_type_name **a, size_t num, size_t cap) { \
		*a = _ps4_array_resize(&(*a)->hdr, ps4_array_item_size(*a), num, cap);\
	}								\
	static inline void						\
	array_type_name##_copy(struct array_type_name **dst, struct array_type_name *src) { \
		if (*dst == src) return;				\
		_ps4_array_free(&(*dst)->hdr);				\
		*dst = _ps4_array_copy(&src->hdr, ps4_array_item_size(src)); \
	}								\
	static inline item_type_name *					\
	array_type_name##_add(struct array_type_name **a, item_type_name item) {\
		if ((*a)->hdr.num >= (*a)->hdr.capacity) *a = _ps4_array_grow(&(*a)->hdr, ps4_array_item_size(*a)); \
		item_type_name *nitem = &(*a)->item[((*a)->hdr.num)++];	\
		*nitem = item;						\
		return nitem;						\
	}

PS4_ARRAY(ps4_string_array, char *);

#define foreach_array_item(iter, array) \
	for (iter = &(array)->item[0]; iter < &(array)->item[(array)->hdr.num]; iter++)

#define LIST_HEAD(name) struct list_head name = { &name, &name }
#define LIST_END (void *) 0xe01
#define LIST_POISON1 (void *) 0xdeadbeef
#define LIST_POISON2 (void *) 0xabbaabba

struct hlist_node {
	struct hlist_node *next;
};

struct hlist_head {
	struct hlist_node *first;
};

static inline int hlist_empty(const struct hlist_head *h)
{
	return !h->first;
}

static inline int hlist_hashed(const struct hlist_node *n)
{
	return n->next != NULL;
}

static inline void __hlist_del(struct hlist_node *n, struct hlist_node **pprev)
{
	*pprev = n->next;
	n->next = NULL;
}

static inline void hlist_del(struct hlist_node *n, struct hlist_head *h)
{
	struct hlist_node **pp = &h->first;

	while (*pp != NULL && *pp != LIST_END && *pp != n)
		pp = &(*pp)->next;

	if (*pp == n)
		__hlist_del(n, pp);
}

static inline void hlist_add_head(struct hlist_node *n, struct hlist_head *h)
{
	struct hlist_node *first = h->first;

	n->next = first ? first : LIST_END;
	h->first = n;
}

static inline void hlist_add_after(struct hlist_node *n, struct hlist_node **prev)
{
	n->next = *prev ? *prev : LIST_END;
	*prev = n;
}

static inline struct hlist_node **hlist_tail_ptr(struct hlist_head *h)
{
	struct hlist_node *n = h->first;
	if (n == NULL || n == LIST_END)
		return &h->first;
	while (n->next != NULL && n->next != LIST_END)
		n = n->next;
	return &n->next;
}

#define hlist_entry(ptr, type, member) container_of(ptr,type,member)

#define hlist_for_each(pos, head) \
	for (pos = (head)->first; pos && pos != LIST_END; \
	     pos = pos->next)

#define hlist_for_each_safe(pos, n, head) \
	for (pos = (head)->first; pos && pos != LIST_END && \
		({ n = pos->next; 1; }); \
	     pos = n)

#define hlist_for_each_entry(tpos, pos, head, member)			 \
	for (pos = (head)->first;					 \
	     pos && pos != LIST_END  &&					 \
		({ tpos = hlist_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = pos->next)

#define hlist_for_each_entry_safe(tpos, pos, n, head, member) 		 \
	for (pos = (head)->first;					 \
	     pos && pos != LIST_END && ({ n = pos->next; 1; }) && 	 \
		({ tpos = hlist_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = n)


struct list_head {
	struct list_head *next, *prev;
};

static inline void list_init(struct list_head *list)
{
	list->next = list;
	list->prev = list;
}

static inline void __list_add(struct list_head *new,
			      struct list_head *prev,
			      struct list_head *next)
{
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}

static inline void list_add(struct list_head *new, struct list_head *head)
{
	__list_add(new, head, head->next);
}

static inline void list_add_tail(struct list_head *new, struct list_head *head)
{
	__list_add(new, head->prev, head);
}

static inline void __list_del(struct list_head *prev, struct list_head *next)
{
	next->prev = prev;
	prev->next = next;
}

static inline void list_del(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
	entry->next = LIST_POISON1;
	entry->prev = LIST_POISON2;
}

static inline void list_del_init(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
	entry->next = NULL;
	entry->prev = NULL;
}

static inline int list_hashed(const struct list_head *n)
{
	return n->next != n && n->next != NULL;
}

static inline int list_empty(const struct list_head *n)
{
	return n->next == n;
}

static inline struct list_head *__list_pop(struct list_head *head)
{
	struct list_head *n = head->next;
	list_del_init(n);
	return n;
}

#define list_entry(ptr, type, member) container_of(ptr,type,member)

#define list_pop(head, type, member) container_of(__list_pop(head),type,member)

#define list_for_each(pos, head) \
	for (pos = (head)->next; pos != (head); pos = pos->next)

#define list_for_each_safe(pos, n, head) \
	for (pos = (head)->next, n = pos->next; pos != (head); \
		pos = n, n = pos->next)

#define list_for_each_entry(pos, head, member)				\
	for (pos = list_entry((head)->next, typeof(*pos), member);	\
	     &pos->member != (head); 					\
	     pos = list_entry(pos->member.next, typeof(*pos), member))

#define list_for_each_entry_safe(pos, n, head, member)			\
	for (pos = list_entry((head)->next, typeof(*pos), member),	\
		n = list_entry(pos->member.next, typeof(*pos), member);	\
	     &pos->member != (head); 					\
	     pos = n, n = list_entry(n->member.next, typeof(*n), member))

#endif
