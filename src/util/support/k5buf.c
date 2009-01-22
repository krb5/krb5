/* -*- mode: c; indent-tabs-mode: nil -*- */

/*
 * k5buf.c
 *
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
 *
 * Implement the k5buf string buffer module.
 */

/* Can't include krb5.h here, or k5-int.h which includes it, because
   krb5.h needs to be generated with error tables, after util/et,
   which builds after this directory.  */
#include "k5buf-int.h"
#include <assert.h>

/* Structure invariants:

   buftype is FIXED, DYNAMIC, or ERROR
   if buftype is not ERROR:
     space > 0
     space <= floor(SIZE_MAX / 2) (to fit within ssize_t)
     len < space
     data[len] = '\0'
*/

/* Make sure there is room for LEN more characters in BUF, in addition
   to the null terminator and what's already in there.  Return true on
   success.  On failure, set the error flag and return false. */
static int ensure_space(struct k5buf *buf, size_t len)
{
    size_t new_space;
    char *new_data;

    if (buf->buftype == ERROR)
        return 0;
    if (buf->space - 1 - buf->len >= len) /* Enough room already. */
        return 1;
    if (buf->buftype == FIXED) /* Can't resize a fixed buffer. */
        goto error_exit;
    assert(buf->buftype == DYNAMIC);
    new_space = buf->space * 2;
    while (new_space <= SPACE_MAX && new_space - buf->len - 1 < len)
        new_space *= 2;
    if (new_space > SPACE_MAX)
        goto error_exit;
    new_data = realloc(buf->data, new_space);
    if (new_data == NULL)
        goto error_exit;
    buf->data = new_data;
    buf->space = new_space;
    return 1;

 error_exit:
    if (buf->buftype == DYNAMIC) {
        free(buf->data);
        buf->data = NULL;
    }
    buf->buftype = ERROR;
    return 0;
}

void krb5int_buf_init_fixed(struct k5buf *buf, char *data, size_t space)
{
    assert(space > 0);
    buf->buftype = FIXED;
    buf->data = data;
    buf->space = space;
    buf->len = 0;
    buf->data[0] = '\0';
}

void krb5int_buf_init_dynamic(struct k5buf *buf)
{
    buf->buftype = DYNAMIC;
    buf->space = DYNAMIC_INITIAL_SIZE;
    buf->data = malloc(buf->space);
    if (buf->data == NULL) {
        buf->buftype = ERROR;
        return;
    }
    buf->len = 0;
    buf->data[0] = '\0';
}

void krb5int_buf_add(struct k5buf *buf, const char *data)
{
    krb5int_buf_add_len(buf, data, strlen(data));
}

void krb5int_buf_add_len(struct k5buf *buf, const char *data, size_t len)
{
    if (!ensure_space(buf, len))
        return;
    memcpy(buf->data + buf->len, data, len);
    buf->len += len;
    buf->data[buf->len] = '\0';
}

void krb5int_buf_add_fmt(struct k5buf *buf, const char *fmt, ...)
{
    va_list ap;
    int r;
    size_t remaining;
    char *tmp;

    if (buf->buftype == ERROR)
        return;
    remaining = buf->space - buf->len;

    if (buf->buftype == FIXED) {
        /* Format the data directly into the fixed buffer. */
        va_start(ap, fmt);
        r = vsnprintf(buf->data + buf->len, remaining, fmt, ap);
        va_end(ap);
        if (SNPRINTF_OVERFLOW(r, remaining))
            buf->buftype = ERROR;
        else
            buf->len += (unsigned int) r;
        return;
    }

    /* Optimistically format the data directly into the dynamic buffer. */
    assert(buf->buftype == DYNAMIC);
    va_start(ap, fmt);
    r = vsnprintf(buf->data + buf->len, remaining, fmt, ap);
    va_end(ap);
    if (!SNPRINTF_OVERFLOW(r, remaining)) {
        buf->len += (unsigned int) r;
        return;
    }

    if (r >= 0) {
        /* snprintf correctly told us how much space is required. */
        if (!ensure_space(buf, r))
            return;
        remaining = buf->space - buf->len;
        va_start(ap, fmt);
        r = vsnprintf(buf->data + buf->len, remaining, fmt, ap);
        va_end(ap);
        if (SNPRINTF_OVERFLOW(r, remaining))  /* Shouldn't ever happen. */
            buf->buftype = ERROR;
        else
            buf->len += (unsigned int) r;
        return;
    }

    /* It's a pre-C99 snprintf implementation, or something else went
       wrong.  Fall back to asprintf. */
    va_start(ap, fmt);
    r = vasprintf(&tmp, fmt, ap);
    va_end(ap);
    if (r < 0) {
        buf->buftype = ERROR;
        return;
    }
    if (ensure_space(buf, r)) {
        /* Copy the temporary string into buf, including terminator. */
        memcpy(buf->data + buf->len, tmp, r + 1);
        buf->len += r;
    }
    free(tmp);
}

void krb5int_buf_truncate(struct k5buf *buf, size_t len)
{
    if (buf->buftype == ERROR)
        return;
    assert(len <= buf->len);
    buf->len = len;
    buf->data[buf->len] = '\0';
}


char *krb5int_buf_data(struct k5buf *buf)
{
    return (buf->buftype == ERROR) ? NULL : buf->data;
}

ssize_t krb5int_buf_len(struct k5buf *buf)
{
    return (buf->buftype == ERROR) ? -1 : (ssize_t) buf->len;
}

void krb5int_free_buf(struct k5buf *buf)
{
    if (buf->buftype == ERROR)
        return;
    assert(buf->buftype == DYNAMIC);
    free(buf->data);
    buf->data = NULL;
    buf->buftype = ERROR;
}
