/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* include/k5-buf.h - k5buf interface declarations */
/*
 * Copyright 2008 Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

#ifndef K5_BUF_H
#define K5_BUF_H

#if defined(_MSDOS) || defined(_WIN32)
#include <win-mac.h>
#endif
#ifndef KRB5_CALLCONV
#define KRB5_CALLCONV
#define KRB5_CALLCONV_C
#endif

#include <stdarg.h>
#include <string.h>
#ifndef _WIN32
#include <unistd.h>
#endif

/*
 * The k5buf module is intended to allow multi-step string construction in a
 * fixed or dynamic buffer without the need to check for a failure at each step
 * (and without aborting on malloc failure).  If an allocation failure occurs
 * or if the fixed buffer runs out of room, the error will be discovered when
 * the caller retrieves the C string value or checks the length of the
 * resulting buffer.
 *
 * k5buf structures are stack-allocated, but are intended to be opaque, so do
 * not access the fields directly.  This is a tool, not a way of life, so do
 * not put k5buf structure pointers into the public API or into significant
 * internal APIs.
 */

/*
 * We must define the k5buf structure here to allow stack allocation.  The
 * structure is intended to be opaque, so the fields have funny names.
 */
struct k5buf {
    int xx_buftype;
    char *xx_data;
    size_t xx_space;
    size_t xx_len;
};

/** Initialize a k5buf using a fixed-sized, existing buffer.  SPACE must be
 * more than zero, or an assertion failure will result. */
void krb5int_buf_init_fixed(struct k5buf *buf, char *data, size_t space);

/** Initialize a k5buf using an internally allocated dynamic buffer.  The
 * buffer contents must be freed with krb5int_free_buf. */
void krb5int_buf_init_dynamic(struct k5buf *buf);

/** Add a C string to BUF. */
void krb5int_buf_add(struct k5buf *buf, const char *data);

/**
 * Add a counted set of bytes to BUF.  It is okay for DATA[0..LEN-1]
 * to contain null bytes if you are prepared to deal with that in the
 * output (use krb5int_buf_len to retrieve the length of the output).
 */
void krb5int_buf_add_len(struct k5buf *buf, const char *data, size_t len);

/** Add sprintf-style formatted data to BUF. */
void krb5int_buf_add_fmt(struct k5buf *buf, const char *fmt, ...)
#if !defined(__cplusplus) && (__GNUC__ > 2)
    __attribute__((__format__(__printf__, 2, 3)))
#endif
    ;

/** Truncate BUF.  LEN must be between 0 and the existing buffer
 * length, or an assertion failure will result. */
void krb5int_buf_truncate(struct k5buf *buf, size_t len);

/**
 * Retrieve the byte array value of BUF, or NULL if there has been an
 * allocation failure or the fixed buffer ran out of room.

 * The byte array will be a C string unless binary data was added with
 * krb5int_buf_add_len; it will be null-terminated regardless.
 * Modifying the byte array does not invalidate the buffer, as long as
 * its length is not changed.

 * For a fixed buffer, the return value will always be equal to the
 * passed-in value of DATA at initialization time if it is not NULL.

 * For a dynamic buffer, any buffer modification operation except
 * krb5int_buf_truncate may invalidate the byte array address.
 */
char *krb5int_buf_data(struct k5buf *buf);

/**
 * Retrieve the length of BUF, or -1 if there has been an allocation
 * failure or the fixed buffer ran out of room.  The length is equal
 * to strlen(krb5int_buf_data(buf)) unless binary data was added with
 * krb5int_buf_add_len.
 */
ssize_t krb5int_buf_len(struct k5buf *buf);

/**
 * Free the storage used in the dynamic buffer BUF.  The caller may
 * choose to take responsibility for freeing the return value of
 * krb5int_buf_data instead of using this function.  If BUF is a fixed
 * buffer, an assertion failure will result.  It is unnecessary
 * (though harmless) to free a buffer after an error is detected; the
 * storage will already have been freed in that case.
 */
void krb5int_free_buf(struct k5buf *buf);

#endif /* K5_BUF_H */
