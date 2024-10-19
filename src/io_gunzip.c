/* io_gunzip.c - PS4linux package manager (PS4)
 *
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <zlib.h>

#include "ps4_defines.h"
#include "ps4_io.h"

struct ps4_gzip_istream {
	struct ps4_istream is;
	struct ps4_istream *zis;
	z_stream zs;

	ps4_multipart_cb cb;
	void *cbctx;
	void *cbprev;
	ps4_blob_t cbarg;
};

static void gzi_get_meta(struct ps4_istream *is, struct ps4_file_meta *meta)
{
	struct ps4_gzip_istream *gis = container_of(is, struct ps4_gzip_istream, is);
	ps4_istream_get_meta(gis->zis, meta);
}

static int gzi_boundary_change(struct ps4_gzip_istream *gis)
{
	int r;

	if (gis->cb && !ps4_BLOB_IS_NULL(gis->cbarg)) {
		r = gis->cb(gis->cbctx, PS4_MPART_DATA, gis->cbarg);
		if (r) return ps4_istream_error(&gis->is, r);
	}
	gis->cbarg = PS4_BLOB_NULL;
	if (!gis->is.err && gis->zis->err && gis->zs.avail_in == 0) gis->is.err = gis->zis->err;
	if (!gis->cb) return 0;
	r = gis->cb(gis->cbctx, gis->is.err ? PS4_MPART_END : PS4_MPART_BOUNDARY, PS4_BLOB_NULL);
	if (r > 0) r = -ECANCELED;
	return ps4_istream_error(&gis->is, r);
}

static int gzi_read_more(struct ps4_gzip_istream *gis)
{
	ps4_blob_t blob;
	int r;

	r = ps4_istream_get_all(gis->zis, &blob);
	if (r < 0) {
		if (r != -PS4E_EOF) return ps4_istream_error(&gis->is, r);
		return 0;
	}
	gis->zs.avail_in = blob.len;
	gis->zs.next_in = (void *) blob.ptr;
	gis->cbprev = blob.ptr;
	return 0;
}

static ssize_t gzi_read(struct ps4_istream *is, void *ptr, size_t size)
{
	struct ps4_gzip_istream *gis = container_of(is, struct ps4_gzip_istream, is);
	int r;

	gis->zs.avail_out = size;
	gis->zs.next_out  = ptr;

	while (gis->zs.avail_out != 0 && gis->is.err >= 0) {
		if (!PS4_BLOB_IS_NULL(gis->cbarg)) {
			r = gzi_boundary_change(gis);
			if (r) return r;
		}
		if (gis->zs.avail_in == 0 && gis->is.err == 0) {
			if (gis->cb != NULL && gis->cbprev != NULL && gis->cbprev != gis->zs.next_in) {
				r = gis->cb(gis->cbctx, PS4_MPART_DATA,
					PS4_BLOB_PTR_LEN(gis->cbprev, (void *)gis->zs.next_in - gis->cbprev));
				if (r < 0) return ps4_istream_error(&gis->is, r);
				gis->cbprev = gis->zs.next_in;
			}
			r = gzi_read_more(gis);
			if (r) return r;
		}

		r = inflate(&gis->zs, Z_NO_FLUSH);
		switch (r) {
		case Z_STREAM_END:
			if (gis->cb != NULL) {
				gis->cbarg = PS4_BLOB_PTR_LEN(gis->cbprev, (void *) gis->zs.next_in - gis->cbprev);
				gis->cbprev = gis->zs.next_in;
			}
			/* Digest the inflated bytes */
			if (gis->zs.avail_in == 0) {
				r = gzi_read_more(gis);
				if (r) return r;
			}
			/* If we hit end of the bitstream (not end
			 * of just this gzip), we need to do the
			 * callback here, as we won't be called again.
			 * For boundaries it should be postponed to not
			 * be called until next gzip read is started. */
			if (gis->zs.avail_in == 0 && gis->zs.avail_out == size) {
				r = gzi_boundary_change(gis);
				if (r) return r;
			}
			inflateEnd(&gis->zs);
			if (inflateInit2(&gis->zs, 15+32) != Z_OK)
				return -ENOMEM;
			if (gis->cb && gis->zs.avail_out != size) goto ret;
			break;
		case Z_OK:
			break;
		case Z_BUF_ERROR:
			/* Happens when input stream is EOF, input buffer is empty,
			 * and we just tried reading a new header. */
			goto ret;
		default:
			return ps4_istream_error(&gis->is, -PS4E_FORMAT_INVALID);
		}
	}

ret:
	return size - gis->zs.avail_out;
}

static int gzi_close(struct ps4_istream *is)
{
	int r;
	struct ps4_gzip_istream *gis = container_of(is, struct ps4_gzip_istream, is);

	inflateEnd(&gis->zs);
	r = ps4_istream_close_error(gis->zis, gis->is.err);
	free(gis);
	return r;
}

static const struct ps4_istream_ops gunzip_istream_ops = {
	.get_meta = gzi_get_meta,
	.read = gzi_read,
	.close = gzi_close,
};

static int window_bits(int window_bits, int raw)
{
	if (raw) return -window_bits;	// raw mode
	return window_bits | 16;	// gzip mode
}

struct ps4_istream *ps4_istream_zlib(struct ps4_istream *is, int raw, ps4_multipart_cb cb, void *ctx)
{
	struct ps4_gzip_istream *gis;

	if (IS_ERR(is)) return ERR_CAST(is);

	gis = malloc(sizeof(*gis) + ps4_io_bufsize);
	if (!gis) goto err;

	*gis = (struct ps4_gzip_istream) {
		.is.ops = &gunzip_istream_ops,
		.is.buf = (uint8_t*)(gis + 1),
		.is.buf_size = ps4_io_bufsize,
		.zis = is,
		.cb = cb,
		.cbctx = ctx,
	};

	if (inflateInit2(&gis->zs, window_bits(15, raw)) != Z_OK) {
		free(gis);
		goto err;
	}

	return &gis->is;
err:
	return ERR_PTR(ps4_istream_close_error(is, -ENOMEM));
}

struct ps4_gzip_ostream {
	struct ps4_ostream os;
	struct ps4_ostream *output;
	z_stream zs;
};

static int gzo_write(struct ps4_ostream *os, const void *ptr, size_t size)
{
	struct ps4_gzip_ostream *gos = container_of(os, struct ps4_gzip_ostream, os);
	unsigned char buffer[1024];
	ssize_t have, r;

	gos->zs.avail_in = size;
	gos->zs.next_in = (void *) ptr;
	while (gos->zs.avail_in) {
		gos->zs.avail_out = sizeof(buffer);
		gos->zs.next_out = buffer;
		r = deflate(&gos->zs, Z_NO_FLUSH);
		if (r == Z_STREAM_ERROR)
			return ps4_ostream_cancel(gos->output, -EIO);
		have = sizeof(buffer) - gos->zs.avail_out;
		if (have != 0) {
			r = ps4_ostream_write(gos->output, buffer, have);
			if (r < 0) return r;
		}
	}

	return 0;
}

static int gzo_close(struct ps4_ostream *os)
{
	struct ps4_gzip_ostream *gos = container_of(os, struct ps4_gzip_ostream, os);
	unsigned char buffer[1024];
	size_t have;
	int r, rc = os->rc;

	do {
		gos->zs.avail_out = sizeof(buffer);
		gos->zs.next_out = buffer;
		r = deflate(&gos->zs, Z_FINISH);
		have = sizeof(buffer) - gos->zs.avail_out;
		if (ps4_ostream_write(gos->output, buffer, have) < 0)
			break;
	} while (r == Z_OK);
	r = ps4_ostream_close(gos->output);
	deflateEnd(&gos->zs);
	free(gos);

	return rc ?: r;
}

static const struct ps4_ostream_ops gzip_ostream_ops = {
	.write = gzo_write,
	.close = gzo_close,
};

struct ps4_ostream *ps4_ostream_zlib(struct ps4_ostream *output, int raw, uint8_t level)
{
	struct ps4_gzip_ostream *gos;

	if (IS_ERR(output)) return ERR_CAST(output);

	gos = malloc(sizeof(struct ps4_gzip_ostream));
	if (gos == NULL) goto err;

	*gos = (struct ps4_gzip_ostream) {
		.os.ops = &gzip_ostream_ops,
		.output = output,
	};

	if (deflateInit2(&gos->zs, level ?: 9, Z_DEFLATED, window_bits(15, raw), 8,
			 Z_DEFAULT_STRATEGY) != Z_OK) {
		free(gos);
		goto err;
	}

	return &gos->os;
err:
	ps4_ostream_close(output);
	return ERR_PTR(-ENOMEM);
}

