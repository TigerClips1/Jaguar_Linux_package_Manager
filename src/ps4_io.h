/* ps4_io.h - PS4linux package manager (PS4)
 *
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef PS4_IO
#define PS4_IO

#include <sys/types.h>
#include <fcntl.h>
#include <time.h>

#include "ps4_defines.h"
#include "ps4_blob.h"
#include "ps4_atom.h"
#include "ps4_crypto.h"

int ps4_make_dirs(int root_fd, const char *dirname, mode_t dirmode, mode_t parentmode);
ssize_t ps4_write_fully(int fd, const void *ptr, size_t size);

struct ps4_id_hash {
	int empty;
	struct hlist_head by_id[16], by_name[16];
};

struct ps4_id_cache {
	int root_fd;
	struct ps4_id_hash uid_cache;
	struct ps4_id_hash gid_cache;
};

struct ps4_xattr {
	const char *name;
	ps4_blob_t value;
};
PS4_ARRAY(ps4_xattr_array, struct ps4_xattr);

struct ps4_file_meta {
	time_t mtime, atime;
};

struct ps4_file_info {
	const char *name;
	const char *link_target;
	const char *uname;
	const char *gname;
	off_t size;
	uid_t uid;
	gid_t gid;
	mode_t mode;
	time_t mtime;
	dev_t device;
	struct ps4_digest digest;
	struct ps4_digest xattr_digest;
	struct ps4_xattr_array *xattrs;
};

extern size_t ps4_io_bufsize;

struct ps4_istream;
struct ps4_ostream;

struct ps4_istream_ops {
	void (*get_meta)(struct ps4_istream *is, struct ps4_file_meta *meta);
	ssize_t (*read)(struct ps4_istream *is, void *ptr, size_t size);
	int (*close)(struct ps4_istream *is);
};

#define PS4_ISTREAM_SINGLE_READ			0x0001

struct ps4_istream {
	uint8_t *ptr, *end, *buf;
	size_t buf_size;
	int err;
	unsigned int flags;
	const struct ps4_istream_ops *ops;
};

typedef int (*ps4_archive_entry_parser)(void *ctx,
					const struct ps4_file_info *ae,
					struct ps4_istream *istream);

#define PS4_IO_ALL ((size_t)-1)

#define PS4_ISTREAM_FORCE_REFRESH		((time_t) -1)

struct ps4_istream *ps4_istream_from_blob(struct ps4_istream *, ps4_blob_t);
struct ps4_istream *__ps4_istream_from_file(int atfd, const char *file, int try_mmap);
static inline struct ps4_istream *ps4_istream_from_file(int atfd, const char *file) { return __ps4_istream_from_file(atfd, file, 0); }
static inline struct ps4_istream *ps4_istream_from_file_mmap(int atfd, const char *file) { return __ps4_istream_from_file(atfd, file, 1); }
struct ps4_istream *ps4_istream_from_fd(int fd);
struct ps4_istream *ps4_istream_from_fd_url_if_modified(int atfd, const char *url, time_t since);
static inline int ps4_istream_error(struct ps4_istream *is, int err) { if (is->err >= 0 && err) is->err = err; return is->err < 0 ? is->err : 0; }
ps4_blob_t ps4_istream_mmap(struct ps4_istream *is);
ssize_t ps4_istream_read_max(struct ps4_istream *is, void *ptr, size_t size);
int ps4_istream_read(struct ps4_istream *is, void *ptr, size_t size);
void *ps4_istream_peek(struct ps4_istream *is, size_t len);
void *ps4_istream_get(struct ps4_istream *is, size_t len);
int ps4_istream_get_max(struct ps4_istream *is, size_t size, ps4_blob_t *data);
int ps4_istream_get_delim(struct ps4_istream *is, ps4_blob_t token, ps4_blob_t *data);
static inline int ps4_istream_get_all(struct ps4_istream *is, ps4_blob_t *data) { return ps4_istream_get_max(is, PS4_IO_ALL, data); }
ssize_t ps4_stream_copy(struct ps4_istream *is, struct ps4_ostream *os, size_t size,
			ps4_progress_cb cb, void *cb_ctx, struct ps4_digest_ctx *dctx);

static inline struct ps4_istream *ps4_istream_from_url(const char *url, time_t since)
{
	return ps4_istream_from_fd_url_if_modified(AT_FDCWD, url, since);
}
static inline struct ps4_istream *ps4_istream_from_fd_url(int atfd, const char *url, time_t since)
{
	return ps4_istream_from_fd_url_if_modified(atfd, url, since);
}
static inline void ps4_istream_get_meta(struct ps4_istream *is, struct ps4_file_meta *meta)
{
	is->ops->get_meta(is, meta);
}
static inline int ps4_istream_close(struct ps4_istream *is)
{
	return is->ops->close(is);
}
static inline int ps4_istream_close_error(struct ps4_istream *is, int r)
{
	if (r < 0) ps4_istream_error(is, r);
	return ps4_istream_close(is);
}

void ps4_io_url_init(void);
void ps4_io_url_set_timeout(int timeout);
void ps4_io_url_set_redirect_callback(void (*cb)(int, const char *));
void ps4_io_url_no_check_certificate(void);
struct ps4_istream *ps4_io_url_istream(const char *url, time_t since);

struct ps4_segment_istream {
	struct ps4_istream is;
	struct ps4_istream *pis;
	size_t bytes_left;
	time_t mtime;
};
struct ps4_istream *ps4_istream_segment(struct ps4_segment_istream *sis, struct ps4_istream *is, size_t len, time_t mtime);

struct ps4_digest_istream {
	struct ps4_istream is;
	struct ps4_istream *pis;
	struct ps4_digest *digest;
	struct ps4_digest_ctx dctx;
	off_t size_left;
};
struct ps4_istream *ps4_istream_verify(struct ps4_digest_istream *dis, struct ps4_istream *is, off_t size, struct ps4_digest *d);

#define PS4_ISTREAM_TEE_COPY_META 1
#define PS4_ISTREAM_TEE_OPTIONAL  2

struct ps4_istream *ps4_istream_tee(struct ps4_istream *from, struct ps4_ostream *to, int copy_meta,
				    ps4_progress_cb cb, void *cb_ctx);

struct ps4_ostream_ops {
	void (*set_meta)(struct ps4_ostream *os, struct ps4_file_meta *meta);
	int (*write)(struct ps4_ostream *os, const void *buf, size_t size);
	int (*close)(struct ps4_ostream *os);
};

struct ps4_ostream {
	const struct ps4_ostream_ops *ops;
	int rc;
};

struct ps4_ostream *ps4_ostream_counter(off_t *);
struct ps4_ostream *ps4_ostream_to_fd(int fd);
struct ps4_ostream *ps4_ostream_to_file(int atfd, const char *file, mode_t mode);
ssize_t ps4_ostream_write_string(struct ps4_ostream *os, const char *string);
void ps4_ostream_copy_meta(struct ps4_ostream *os, struct ps4_istream *is);
static inline int ps4_ostream_error(struct ps4_ostream *os) { return os->rc; }
static inline int ps4_ostream_cancel(struct ps4_ostream *os, int rc) { if (!os->rc) os->rc = rc; return rc; }
static inline int ps4_ostream_write(struct ps4_ostream *os, const void *buf, size_t size) {
	return os->ops->write(os, buf, size);
}
static inline int ps4_ostream_close(struct ps4_ostream *os)
{
	int rc = os->rc;
	return os->ops->close(os) ?: rc;
}
static inline int ps4_ostream_close_error(struct ps4_ostream *os, int r)
{
	ps4_ostream_cancel(os, r);
	return ps4_ostream_close(os);
}

int ps4_blob_from_istream(struct ps4_istream *is, size_t size, ps4_blob_t *b);
int ps4_blob_from_file(int atfd, const char *file, ps4_blob_t *b);

#define PS4_BTF_ADD_EOL		0x00000001
int ps4_blob_to_file(int atfd, const char *file, ps4_blob_t b, unsigned int flags);

#define PS4_FI_NOFOLLOW		0x80000000
#define PS4_FI_XATTR_DIGEST(x)	(((x) & 0xff) << 8)
#define PS4_FI_DIGEST(x)	(((x) & 0xff))
int ps4_fileinfo_get(int atfd, const char *filename, unsigned int flags,
		     struct ps4_file_info *fi, struct ps4_atom_pool *atoms);
void ps4_fileinfo_hash_xattr(struct ps4_file_info *fi, uint8_t alg);

typedef int ps4_dir_file_cb(void *ctx, int dirfd, const char *entry);
int ps4_dir_foreach_file(int dirfd, ps4_dir_file_cb cb, void *ctx);

const char *ps4_url_local_file(const char *url);

void ps4_id_cache_init(struct ps4_id_cache *idc, int root_fd);
void ps4_id_cache_free(struct ps4_id_cache *idc);
void ps4_id_cache_reset(struct ps4_id_cache *idc);
uid_t ps4_id_cache_resolve_uid(struct ps4_id_cache *idc, ps4_blob_t username, uid_t default_uid);
gid_t ps4_id_cache_resolve_gid(struct ps4_id_cache *idc, ps4_blob_t groupname, gid_t default_gid);
ps4_blob_t ps4_id_cache_resolve_user(struct ps4_id_cache *idc, uid_t uid);
ps4_blob_t ps4_id_cache_resolve_group(struct ps4_id_cache *idc, gid_t gid);

// Gzip support

#define PS4_MPART_DATA		1 /* data processed so far */
#define PS4_MPART_BOUNDARY	2 /* final part of data, before boundary */
#define PS4_MPART_END		3 /* signals end of stream */

typedef int (*ps4_multipart_cb)(void *ctx, int part, ps4_blob_t data);

struct ps4_istream *ps4_istream_zlib(struct ps4_istream *, int,
				     ps4_multipart_cb cb, void *ctx);
static inline struct ps4_istream *ps4_istream_gunzip_mpart(struct ps4_istream *is,
					     ps4_multipart_cb cb, void *ctx) {
	return ps4_istream_zlib(is, 0, cb, ctx);
}
static inline struct ps4_istream *ps4_istream_gunzip(struct ps4_istream *is) {
	return ps4_istream_zlib(is, 0, NULL, NULL);
}
static inline struct ps4_istream *ps4_istream_deflate(struct ps4_istream *is) {
	return ps4_istream_zlib(is, 1, NULL, NULL);
}

struct ps4_ostream *ps4_ostream_zlib(struct ps4_ostream *, int, uint8_t);
static inline struct ps4_ostream *ps4_ostream_gzip(struct ps4_ostream *os) {
	return ps4_ostream_zlib(os, 0, 0);
}
static inline struct ps4_ostream *ps4_ostream_deflate(struct ps4_ostream *os, uint8_t level) {
	return ps4_ostream_zlib(os, 1, level);
}

struct ps4_istream *ps4_istream_zstd(struct ps4_istream *);
struct ps4_ostream *ps4_ostream_zstd(struct ps4_ostream *, uint8_t);

#endif
