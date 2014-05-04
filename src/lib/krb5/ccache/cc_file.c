/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/krb5/ccache/cc_file.c - File-based credential cache */
/*
 * Copyright 1990,1991,1992,1993,1994,2000,2004,2007 Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Original stdio support copyright 1995 by Cygnus Support.
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

/*
 * A psuedo-BNF grammar for the FILE credential cache format is:
 *
 * file ::=
 *   version (2 bytes; 05 01 for version 1 through 05 04 for version 4)
 *   header [not present before version 4]
 *   principal
 *   credential1
 *   credential2
 *   ...
 *
 * header ::=
 *   headerlen (16 bits)
 *   header1tag (16 bits)
 *   header1len (16 bits)
 *   header1val (header1len bytes)
 *
 * See ccmarshal.c for the principal and credential formats.  Although versions
 * 1 and 2 of the FILE format use native byte order for integer representations
 * within principals and credentials, the integer fields in the grammar above
 * are always in big-endian byte order.
 *
 * Only one header tag is currently defined.  The tag value is 1
 * (FCC_TAG_DELTATIME), and its contents are two 32-bit integers giving the
 * seconds and microseconds of the time offset of the KDC relative to the
 * client.
 *
 * If the OPENCLOSE flag is set (as it is by default), each of the file ccache
 * functions opens and closes the file whenever it needs to access it.
 * Otherwise, the file is opened once in initialize and closed once in close.
 *
 * This module depends on UNIX-like file descriptors, and UNIX-like behavior
 * from the functions: open, close, read, write, lseek.
 */

#include "k5-int.h"
#include "cc-int.h"

#include <stdio.h>
#include <errno.h>

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

extern const krb5_cc_ops krb5_cc_file_ops;

krb5_error_code krb5_change_cache(void);

static krb5_error_code read_data(krb5_context, krb5_ccache id,
                                 krb5_data *data);
static krb5_error_code read32(krb5_context, krb5_ccache id, int32_t *i);
static krb5_error_code read16(krb5_context, krb5_ccache id, uint16_t *i);
static krb5_error_code read_addr(krb5_context context, krb5_ccache id,
                                 krb5_address *addr);
static krb5_error_code read_authdatum(krb5_context, krb5_ccache,
                                      krb5_authdata *);
static krb5_error_code store_data(krb5_context, krb5_ccache id,
                                  krb5_data *data);
static krb5_error_code store32(krb5_context, krb5_ccache id, uint32_t i);
static krb5_error_code store16(krb5_context, krb5_ccache id, uint16_t i);
static krb5_error_code store_addr(krb5_context, krb5_ccache, krb5_address *);
static krb5_error_code store_authdatum(krb5_context, krb5_ccache,
                                       krb5_authdata *);
static krb5_error_code interpret_errno(krb5_context, int);

#define FVNO_1 0x0501           /* krb v5, fcc v1 */
#define FVNO_2 0x0502           /* krb v5, fcc v2 */
#define FVNO_3 0x0503           /* krb v5, fcc v3 */
#define FVNO_4 0x0504           /* krb v5, fcc v4 */

#define FCC_OPEN_AND_ERASE      1
#define FCC_OPEN_RDWR           2
#define FCC_OPEN_RDONLY         3

#define FCC_TAG_DELTATIME       1

#ifndef TKT_ROOT
#ifdef MSDOS_FILESYSTEM
#define TKT_ROOT "\\tkt"
#else
#define TKT_ROOT "/tmp/tkt"
#endif
#endif

/* macros to make checking flags easier */
#define OPENCLOSE(id) (((fcc_data *)id->data)->flags & KRB5_TC_OPENCLOSE)

typedef struct fcc_data_st {
    char *filename;

    /* Lock this before reading or modifying the data stored here that can be
     * changed.  (Filename is fixed after initialization.)  */
    k5_cc_mutex lock;
    int fd;
    krb5_flags flags;
    int mode;                   /* needed for locking code */
    int version;                /* version number of the file */

    /*
     * Buffer data on reading, for performance.  We used to have a stdio
     * option, but we get more precise control by using the POSIX I/O
     * functions.
     */
#define FCC_BUFSIZ 1024
    size_t valid_bytes;
    size_t cur_offset;
    char buf[FCC_BUFSIZ];
} fcc_data;

/* Return the file version as an integer from 1 to 4. */
static inline int
version(krb5_ccache id)
{
    return ((fcc_data *)id->data)->version - FVNO_1 + 1;
}

/* Discard cached read information within data. */
static inline void
invalidate_cache(fcc_data *data)
{
    data->valid_bytes = 0;
}

/* Change position within the cache file, taking into account read caching. */
static off_t
fcc_lseek(fcc_data *data, off_t offset, int whence)
{
    /* If we read some extra data in advance, and then want to know or use our
     * "current" position, we need to back up a little.  */
    if (whence == SEEK_CUR && data->valid_bytes) {
        assert(data->cur_offset > 0);
        assert(data->cur_offset <= data->valid_bytes);
        offset -= (data->valid_bytes - data->cur_offset);
    }
    invalidate_cache(data);
    return lseek(data->fd, offset, whence);
}

struct fcc_set {
    struct fcc_set *next;
    fcc_data *data;
    unsigned int refcount;
};

k5_cc_mutex krb5int_cc_file_mutex = K5_CC_MUTEX_PARTIAL_INITIALIZER;
static struct fcc_set *fccs = NULL;

/* Iterator over file caches.  */
struct krb5_fcc_ptcursor_data {
    krb5_boolean first;
};

/* An off_t can be arbitrarily complex */
typedef struct _krb5_fcc_cursor {
    off_t pos;
} krb5_fcc_cursor;

#define MAYBE_OPEN(CONTEXT, ID, MODE)                                   \
    {                                                                   \
        k5_cc_mutex_assert_locked(CONTEXT, &((fcc_data *)(ID)->data)->lock); \
        if (OPENCLOSE(ID)) {                                            \
            krb5_error_code mo_ret;                                     \
            mo_ret = open_cache_file(CONTEXT, ID, MODE);                \
            if (mo_ret) {                                               \
                k5_cc_mutex_unlock(CONTEXT, &((fcc_data *)(ID)->data)->lock); \
                return mo_ret;                                          \
            }                                                           \
        }                                                               \
    }

#define MAYBE_CLOSE(CONTEXT, ID, RET)                                   \
    {                                                                   \
        if (OPENCLOSE(ID)) {                                            \
            krb5_error_code mc_ret;                                     \
            mc_ret = close_cache_file(CONTEXT, (ID)->data);             \
            if (!(RET))                                                 \
                RET = mc_ret;                                           \
        }                                                               \
    }

#define CHECK(ret) if (ret) goto errout;

#define NO_FILE -1

/* Read len bytes from the cache id, storing them in buf.  Return KRB5_CC_END
 * if not enough bytes are present.  Call with the mutex locked. */
static krb5_error_code
read_bytes(krb5_context context, krb5_ccache id, void *buf, unsigned int len)
{
    fcc_data *data = id->data;

    k5_cc_mutex_assert_locked(context, &data->lock);

    while (len > 0) {
        int nread, e;
        size_t ncopied;

        if (data->valid_bytes > 0)
            assert(data->cur_offset <= data->valid_bytes);
        if (data->valid_bytes == 0 || data->cur_offset == data->valid_bytes) {
            /* Fill buffer from current file position.  */
            nread = read(data->fd, data->buf, sizeof(data->buf));
            e = errno;
            if (nread < 0)
                return interpret_errno(context, e);
            if (nread == 0)
                return KRB5_CC_END;
            data->valid_bytes = nread;
            data->cur_offset = 0;
        }
        assert(data->cur_offset < data->valid_bytes);
        ncopied = len;
        assert(ncopied == len);
        if (data->valid_bytes - data->cur_offset < ncopied)
            ncopied = data->valid_bytes - data->cur_offset;
        memcpy(buf, data->buf + data->cur_offset, ncopied);
        data->cur_offset += ncopied;
        assert(data->cur_offset > 0);
        assert(data->cur_offset <= data->valid_bytes);
        len -= ncopied;
        buf = (char *)buf + ncopied;
    }
    return 0;
}

/*
 * FOR ALL OF THE FOLLOWING FUNCTIONS:
 *
 * Requires:
 * id is open and set to read at the appropriate place in the file
 *
 * mutex is locked
 *
 * Effects:
 * Fills in the second argument with data of the appropriate type from
 * the file.  In some cases, the functions have to allocate space for
 * variable length fields; therefore, krb5_destroy_<type> must be
 * called for each filled in structure.
 *
 * Errors:
 * system errors (read errors)
 * KRB5_CC_NOMEM
 */

#define ALLOC(NUM, TYPE)                            \
    (((NUM) <= (((size_t)0 - 1) / sizeof(TYPE))) ?  \
     (TYPE *)calloc((NUM), sizeof(TYPE)) :          \
     (errno = ENOMEM, (TYPE *)0))

static krb5_error_code
read_principal(krb5_context context, krb5_ccache id, krb5_principal *princ)
{
    fcc_data *data = id->data;
    krb5_error_code kret;
    register krb5_principal tmpprinc;
    int32_t length, type;
    int i;

    k5_cc_mutex_assert_locked(context, &data->lock);

    *princ = NULL;

    if (version(id) == 1) {
        type = KRB5_NT_UNKNOWN;
    } else {
        /* Read principal type. */
        kret = read32(context, id, &type);
        if (kret)
            return kret;
    }

    /* Read the number of components. */
    kret = read32(context, id, &length);
    if (kret)
        return kret;

    /*
     * DCE includes the principal's realm in the count; the new format
     * does not.
     */
    if (version(id) == 1)
        length--;
    if (length < 0)
        return KRB5_CC_NOMEM;

    tmpprinc = malloc(sizeof(*tmpprinc));
    if (tmpprinc == NULL)
        return KRB5_CC_NOMEM;
    if (length) {
        size_t msize = length;
        if (msize != (uint32_t)length) {
            free(tmpprinc);
            return KRB5_CC_NOMEM;
        }
        tmpprinc->data = ALLOC(msize, krb5_data);
        if (tmpprinc->data == 0) {
            free(tmpprinc);
            return KRB5_CC_NOMEM;
        }
    } else {
        tmpprinc->data = 0;
    }
    tmpprinc->magic = KV5M_PRINCIPAL;
    tmpprinc->length = length;
    tmpprinc->type = type;

    kret = read_data(context, id, &tmpprinc->realm);

    i = 0;
    CHECK(kret);

    for (i = 0; i < length; i++) {
        kret = read_data(context, id, &tmpprinc->data[i]);
        CHECK(kret);
    }
    *princ = tmpprinc;
    return 0;

errout:
    while (--i >= 0)
        free(tmpprinc->data[i].data);
    free(tmpprinc->realm.data);
    free(tmpprinc->data);
    free(tmpprinc);
    return kret;
}

static krb5_error_code
read_addrs(krb5_context context, krb5_ccache id, krb5_address ***addrs)
{
    krb5_error_code kret;
    int32_t length;
    size_t msize;
    int i;

    k5_cc_mutex_assert_locked(context, &((fcc_data *)id->data)->lock);

    *addrs = NULL;

    /* Read the number of components */
    kret = read32(context, id, &length);
    CHECK(kret);

    /* Make *addrs able to hold length pointers to krb5_address structs
     * Add one extra for a null-terminated list */
    msize = length;
    msize += 1;
    if (msize == 0 || msize - 1 != (uint32_t)length || length < 0)
        return KRB5_CC_NOMEM;
    *addrs = ALLOC(msize, krb5_address *);
    if (*addrs == NULL)
        return KRB5_CC_NOMEM;

    for (i = 0; i < length; i++) {
        (*addrs)[i] = malloc(sizeof(krb5_address));
        if ((*addrs)[i] == NULL) {
            krb5_free_addresses(context, *addrs);
            *addrs = 0;
            return KRB5_CC_NOMEM;
        }
        (*addrs)[i]->contents = NULL;
        kret = read_addr(context, id, (*addrs)[i]);
        CHECK(kret);
    }

    return 0;
errout:
    if (*addrs) {
        krb5_free_addresses(context, *addrs);
        *addrs = NULL;
    }
    return kret;
}

static krb5_error_code
read_keyblock(krb5_context context, krb5_ccache id, krb5_keyblock *keyblock)
{
    krb5_error_code kret;
    uint16_t ui2;
    int32_t int32;

    k5_cc_mutex_assert_locked(context, &((fcc_data *)id->data)->lock);

    keyblock->magic = KV5M_KEYBLOCK;
    keyblock->contents = 0;

    /* Enctype is signed, so sign-extend the 16-bit value we read. */
    kret = read16(context, id, &ui2);
    keyblock->enctype = (int16_t)ui2;
    CHECK(kret);
    if (version(id) == 3) {
        /* This works because the old etype is the same as the new enctype. */
        kret = read16(context, id, &ui2);
        /* keyblock->enctype = ui2; */
        CHECK(kret);
    }

    kret = read32(context, id, &int32);
    CHECK(kret);
    if (int32 < 0)
        return KRB5_CC_NOMEM;
    keyblock->length = int32;
    /* Overflow check.  */
    if (keyblock->length != (uint32_t)int32)
        return KRB5_CC_NOMEM;
    if (keyblock->length == 0)
        return 0;
    keyblock->contents = malloc(keyblock->length);
    if (keyblock->contents == NULL)
        return KRB5_CC_NOMEM;

    kret = read_bytes(context, id, keyblock->contents, keyblock->length);
    if (kret)
        goto errout;

    return 0;

errout:
    if (keyblock->contents) {
        free(keyblock->contents);
        keyblock->contents = NULL;
    }
    return kret;
}

static krb5_error_code
read_data(krb5_context context, krb5_ccache id, krb5_data *data)
{
    krb5_error_code kret;
    int32_t len;

    k5_cc_mutex_assert_locked(context, &((fcc_data *)id->data)->lock);

    data->magic = KV5M_DATA;
    data->data = 0;

    kret = read32(context, id, &len);
    CHECK(kret);
    if (len < 0)
        return KRB5_CC_NOMEM;
    data->length = len;
    if (data->length != (uint32_t)len || data->length + 1 == 0)
        return KRB5_CC_NOMEM;

    if (data->length == 0) {
        data->data = NULL;
        return 0;
    }

    data->data = malloc(data->length + 1);
    if (data->data == NULL)
        return KRB5_CC_NOMEM;

    kret = read_bytes(context, id, data->data, data->length);
    CHECK(kret);

    data->data[data->length] = 0; /* Null terminate, just in case.... */
    return 0;

errout:
    if (data->data) {
        free(data->data);
        data->data = NULL;
    }
    return kret;
}

static krb5_error_code
read_addr(krb5_context context, krb5_ccache id, krb5_address *addr)
{
    krb5_error_code kret;
    uint16_t ui2;
    int32_t int32;

    k5_cc_mutex_assert_locked(context, &((fcc_data *)id->data)->lock);

    addr->magic = KV5M_ADDRESS;
    addr->contents = 0;

    kret = read16(context, id, &ui2);
    CHECK(kret);
    addr->addrtype = ui2;

    kret = read32(context, id, &int32);
    CHECK(kret);
    if ((int32 & VALID_INT_BITS) != int32)     /* Overflow int??? */
        return KRB5_CC_NOMEM;
    addr->length = int32;
    /* Length field is "unsigned int", which may be smaller than 32 bits. */
    if (addr->length != (uint32_t)int32)
        return KRB5_CC_NOMEM;  /* XXX */

    if (addr->length == 0)
        return 0;

    addr->contents = malloc(addr->length);
    if (addr->contents == NULL)
        return KRB5_CC_NOMEM;

    kret = read_bytes(context, id, addr->contents, addr->length);
    CHECK(kret);

    return 0;

errout:
    if (addr->contents) {
        free(addr->contents);
        addr->contents = NULL;
    }
    return kret;
}

/* Load four bytes from the cache file and return their value as a 32-bit
 * signed integer according to the file format. */
static krb5_error_code
read32(krb5_context context, krb5_ccache id, int32_t *out)
{
    krb5_error_code ret;
    char bytes[4];

    k5_cc_mutex_assert_locked(context, &((fcc_data *)id->data)->lock);

    ret = read_bytes(context, id, bytes, 4);
    if (ret)
        return ret;
    *out = (version(id) < 3) ? load_32_n(bytes) : load_32_be(bytes);
    return 0;
}

/* Load two bytes from the cache file and return their value as a 16-bit
 * unsigned integer according to the file format. */
static krb5_error_code
read16(krb5_context context, krb5_ccache id, uint16_t *out)
{
    krb5_error_code ret;
    char bytes[2];

    k5_cc_mutex_assert_locked(context, &((fcc_data *)id->data)->lock);

    ret = read_bytes(context, id, bytes, 2);
    if (ret)
        return ret;
    *out = (version(id) < 3) ? load_16_n(bytes) : load_16_be(bytes);
    return 0;
}

static krb5_error_code
read_octet(krb5_context context, krb5_ccache id, unsigned char *i)
{
    k5_cc_mutex_assert_locked(context, &((fcc_data *)id->data)->lock);
    return read_bytes(context, id, i, 1);
}

static krb5_error_code
read_times(krb5_context context, krb5_ccache id, krb5_ticket_times *t)
{
    fcc_data *data = id->data;
    krb5_error_code retval;
    int32_t i;

    k5_cc_mutex_assert_locked(context, &((fcc_data *)id->data)->lock);

    if (data->version == FVNO_1 || data->version == FVNO_2) {
        return read_bytes(context, id, t, sizeof(krb5_ticket_times));
    } else {
        retval = read32(context, id, &i);
        CHECK(retval);
        t->authtime = i;

        retval = read32(context, id, &i);
        CHECK(retval);
        t->starttime = i;

        retval = read32(context, id, &i);
        CHECK(retval);
        t->endtime = i;

        retval = read32(context, id, &i);
        CHECK(retval);
        t->renew_till = i;
    }
    return 0;
errout:
    return retval;
}

static krb5_error_code
read_authdata(krb5_context context, krb5_ccache id, krb5_authdata ***a)
{
    krb5_error_code kret;
    int32_t length;
    size_t msize;
    int i;

    k5_cc_mutex_assert_locked(context, &((fcc_data *)id->data)->lock);

    *a = 0;

    /* Read the number of components */
    kret = read32(context, id, &length);
    CHECK(kret);

    if (length == 0)
        return 0;

    /* Make *a able to hold length pointers to krb5_authdata structs
     * Add one extra for a null-terminated list. */
    msize = length;
    msize += 1;
    if (msize == 0 || msize - 1 != (uint32_t)length || length < 0)
        return KRB5_CC_NOMEM;
    *a = ALLOC(msize, krb5_authdata *);
    if (*a == NULL)
        return KRB5_CC_NOMEM;

    for (i = 0; i < length; i++) {
        (*a)[i] = malloc(sizeof(krb5_authdata));
        if ((*a)[i] == NULL) {
            krb5_free_authdata(context, *a);
            *a = NULL;
            return KRB5_CC_NOMEM;
        }
        (*a)[i]->contents = NULL;
        kret = read_authdatum(context, id, (*a)[i]);
        CHECK(kret);
    }

    return 0;
errout:
    if (*a) {
        krb5_free_authdata(context, *a);
        *a = NULL;
    }
    return kret;
}

static krb5_error_code
read_authdatum(krb5_context context, krb5_ccache id, krb5_authdata *a)
{
    krb5_error_code kret;
    int32_t int32;
    int16_t ui2; /* negative authorization data types are allowed */

    k5_cc_mutex_assert_locked(context, &((fcc_data *)id->data)->lock);

    a->magic = KV5M_AUTHDATA;
    a->contents = NULL;

    kret = read16(context, id, (uint16_t *)&ui2);
    CHECK(kret);
    a->ad_type = (krb5_authdatatype)ui2;
    kret = read32(context, id, &int32);
    CHECK(kret);
    if ((int32 & VALID_INT_BITS) != int32)     /* Overflow int??? */
        return KRB5_CC_NOMEM;
    a->length = int32;
    /* Value could have gotten truncated if int is smaller than 32 bits.  */
    if (a->length != (uint32_t)int32)
        return KRB5_CC_NOMEM;

    if (a->length == 0)
        return 0;

    a->contents = malloc(a->length);
    if (a->contents == NULL)
        return KRB5_CC_NOMEM;

    kret = read_bytes(context, id, a->contents, a->length);
    CHECK(kret);

    return 0;
errout:
    if (a->contents) {
        free(a->contents);
        a->contents = NULL;
    }
    return kret;

}
#undef CHECK

#define CHECK(ret) if (ret) return ret;

/* Write len bytes from buf into the cache file.  Call with the mutex
 * locked. */
static krb5_error_code
write_bytes(krb5_context context, krb5_ccache id, const void *buf,
            unsigned int len)
{
    int ret;

    k5_cc_mutex_assert_locked(context, &((fcc_data *)id->data)->lock);
    invalidate_cache(id->data);

    ret = write(((fcc_data *)id->data)->fd, buf, len);
    if (ret < 0)
        return interpret_errno(context, errno);
    if ((unsigned int)ret != len)
        return KRB5_CC_WRITE;
    return 0;
}

/*
 * FOR ALL OF THE FOLLOWING FUNCTIONS:
 *
 * Requires:
 * ((fcc_data *)id->data)->fd is open and at the right position.
 *
 * mutex is locked
 *
 * Effects:
 * Stores an encoded version of the second argument in the
 * cache file.
 *
 * Errors:
 * system errors
 */

static krb5_error_code
store_principal(krb5_context context, krb5_ccache id, krb5_principal princ)
{
    fcc_data *data = id->data;
    krb5_error_code ret;
    int32_t i, length, tmp, type;

    k5_cc_mutex_assert_locked(context, &((fcc_data *)id->data)->lock);

    type = princ->type;
    tmp = length = princ->length;

    if (data->version == FVNO_1) {
        /*
         * DCE-compatible format means that the length count
         * includes the realm.  (It also doesn't include the
         * principal type information.)
         */
        tmp++;
    } else {
        ret = store32(context, id, type);
        CHECK(ret);
    }

    ret = store32(context, id, tmp);
    CHECK(ret);

    ret = store_data(context, id, &princ->realm);
    CHECK(ret);

    for (i = 0; i < length; i++) {
        ret = store_data(context, id, &princ->data[i]);
        CHECK(ret);
    }

    return 0;
}

static krb5_error_code
store_addrs(krb5_context context, krb5_ccache id, krb5_address **addrs)
{
    krb5_error_code ret;
    krb5_address **temp;
    int32_t i, length = 0;

    k5_cc_mutex_assert_locked(context, &((fcc_data *)id->data)->lock);

    /* Count the number of components */
    if (addrs) {
        temp = addrs;
        while (*temp++)
            length += 1;
    }

    ret = store32(context, id, length);
    CHECK(ret);
    for (i = 0; i < length; i++) {
        ret = store_addr(context, id, addrs[i]);
        CHECK(ret);
    }

    return 0;
}

static krb5_error_code
store_keyblock(krb5_context context, krb5_ccache id, krb5_keyblock *keyblock)
{
    fcc_data *data = id->data;
    krb5_error_code ret;

    k5_cc_mutex_assert_locked(context, &((fcc_data *)id->data)->lock);

    ret = store16(context, id, keyblock->enctype);
    CHECK(ret);
    if (data->version == FVNO_3) {
        ret = store16(context, id, keyblock->enctype);
        CHECK(ret);
    }
    ret = store32(context, id, keyblock->length);
    CHECK(ret);
    return write_bytes(context, id, keyblock->contents, keyblock->length);
}

static krb5_error_code
store_addr(krb5_context context, krb5_ccache id, krb5_address *addr)
{
    krb5_error_code ret;

    k5_cc_mutex_assert_locked(context, &((fcc_data *)id->data)->lock);

    ret = store16(context, id, addr->addrtype);
    CHECK(ret);
    ret = store32(context, id, addr->length);
    CHECK(ret);
    return write_bytes(context, id, addr->contents, addr->length);
}

static krb5_error_code
store_data(krb5_context context, krb5_ccache id, krb5_data *data)
{
    krb5_error_code ret;

    k5_cc_mutex_assert_locked(context, &((fcc_data *)id->data)->lock);

    ret = store32(context, id, data->length);
    CHECK(ret);
    return write_bytes(context, id, data->data, data->length);
}

/* Store a 32-bit integer into the cache file according to the file format. */
static krb5_error_code
store32(krb5_context context, krb5_ccache id, uint32_t i)
{
    unsigned char buf[4];

    k5_cc_mutex_assert_locked(context, &((fcc_data *)id->data)->lock);

    if (version(id) < 3)
        store_32_n(i, buf);
    else
        store_32_be(i, buf);
    return write_bytes(context, id, buf, 4);
}

/* Store a 16-bit integer into the cache file according to the file format. */
static krb5_error_code
store16(krb5_context context, krb5_ccache id, uint16_t i)
{
    unsigned char buf[2];

    k5_cc_mutex_assert_locked(context, &((fcc_data *)id->data)->lock);

    if (version(id) < 3)
        store_16_n(i, buf);
    else
        store_16_be(i, buf);
    return write_bytes(context, id, buf, 2);
}

static krb5_error_code
store_octet(krb5_context context, krb5_ccache id, unsigned char i)
{
    k5_cc_mutex_assert_locked(context, &((fcc_data *)id->data)->lock);

    return write_bytes(context, id, &i, 1);
}

static krb5_error_code
store_times(krb5_context context, krb5_ccache id, krb5_ticket_times *t)
{
    fcc_data *data = id->data;
    krb5_error_code retval;

    k5_cc_mutex_assert_locked(context, &((fcc_data *)id->data)->lock);

    if (data->version == FVNO_1 || data->version == FVNO_2) {
        return write_bytes(context, id, t, sizeof(krb5_ticket_times));
    } else {
        retval = store32(context, id, t->authtime);
        CHECK(retval);
        retval = store32(context, id, t->starttime);
        CHECK(retval);
        retval = store32(context, id, t->endtime);
        CHECK(retval);
        retval = store32(context, id, t->renew_till);
        CHECK(retval);
        return 0;
    }
}

static krb5_error_code
store_authdata(krb5_context context, krb5_ccache id, krb5_authdata **a)
{
    krb5_error_code ret;
    krb5_authdata **temp;
    int32_t i, length = 0;

    k5_cc_mutex_assert_locked(context, &((fcc_data *)id->data)->lock);

    if (a != NULL) {
        for (temp = a; *temp; temp++)
            length++;
    }

    ret = store32(context, id, length);
    CHECK(ret);
    for (i = 0; i < length; i++) {
        ret = store_authdatum(context, id, a[i]);
        CHECK(ret);
    }
    return 0;
}

static krb5_error_code
store_authdatum(krb5_context context, krb5_ccache id, krb5_authdata *a)
{
    krb5_error_code ret;

    k5_cc_mutex_assert_locked(context, &((fcc_data *)id->data)->lock);

    ret = store16(context, id, a->ad_type);
    CHECK(ret);
    ret = store32(context, id, a->length);
    CHECK(ret);
    return write_bytes(context, id, a->contents, a->length);
}
#undef CHECK

/* Unlock and close the cache file.  Call with the mutex locked. */
static krb5_error_code
close_cache_file(krb5_context context, fcc_data *data)
{
    int st;
    krb5_error_code ret;

    k5_cc_mutex_assert_locked(context, &data->lock);

    if (data->fd == NO_FILE)
        return KRB5_FCC_INTERNAL;

    ret = krb5_unlock_file(context, data->fd);
    st = close(data->fd);
    data->fd = NO_FILE;
    if (ret)
        return ret;

    return st ? interpret_errno(context, errno) : 0;
}

#if defined(ANSI_STDIO) || defined(_WIN32)
#define BINARY_MODE "b"
#else
#define BINARY_MODE ""
#endif

#ifndef HAVE_SETVBUF
#undef setvbuf
#define setvbuf(FILE,BUF,MODE,SIZE)                             \
    ((SIZE) < BUFSIZE ? (abort(),0) : setbuf(FILE, BUF))
#endif

/* Open and lock the cache file.  If mode is FCC_OPEN_AND_ERASE, initialize it
 * with a header.  Call with the mutex locked. */
static krb5_error_code
open_cache_file(krb5_context context, krb5_ccache id, int mode)
{
    krb5_os_context os_ctx = &context->os_context;
    krb5_error_code ret;
    fcc_data *data = id->data;
    char fcc_fvno[2];
    uint16_t fcc_flen, fcc_tag, fcc_taglen;
    int32_t time_offset, usec_offset;
    int f, open_flag, lock_flag, cnt;
    char buf[1024];

    k5_cc_mutex_assert_locked(context, &data->lock);
    invalidate_cache(data);

    if (data->fd != NO_FILE) {
        /* Don't know what state it's in; shut down and start anew. */
        (void)krb5_unlock_file(context, data->fd);
        (void)close(data->fd);
        data->fd = NO_FILE;
    }

    switch (mode) {
    case FCC_OPEN_AND_ERASE:
        unlink(data->filename);
        open_flag = O_CREAT | O_EXCL | O_TRUNC | O_RDWR;
        break;
    case FCC_OPEN_RDWR:
        open_flag = O_RDWR;
        break;
    case FCC_OPEN_RDONLY:
    default:
        open_flag = O_RDONLY;
        break;
    }

    f = THREEPARAMOPEN(data->filename, open_flag | O_BINARY, 0600);
    if (f == NO_FILE) {
        if (errno == ENOENT) {
            ret = KRB5_FCC_NOFILE;
            krb5_set_error_message(context, ret,
                                   _("Credentials cache file '%s' not found"),
                                   data->filename);
            return ret;
        } else {
            return interpret_errno(context, errno);
        }
    }
    set_cloexec_fd(f);

    data->mode = mode;

    if (data->mode == FCC_OPEN_RDONLY)
        lock_flag = KRB5_LOCKMODE_SHARED;
    else
        lock_flag = KRB5_LOCKMODE_EXCLUSIVE;
    ret = krb5_lock_file(context, f, lock_flag);
    if (ret) {
        (void)close(f);
        return ret;
    }

    if (mode == FCC_OPEN_AND_ERASE) {
        /* write the version number */
        store_16_be(context->fcc_default_format, fcc_fvno);
        data->version = context->fcc_default_format;
        cnt = write(f, fcc_fvno, 2);
        if (cnt != 2) {
            ret = (cnt == -1) ? interpret_errno(context, errno) : KRB5_CC_IO;
            goto done;
        }
        data->fd = f;

        if (data->version == FVNO_4) {
            /* V4 of the credentials cache format allows for header tags */
            fcc_flen = 0;

            if (os_ctx->os_flags & KRB5_OS_TOFFSET_VALID)
                fcc_flen += 2 + 2 + 4 + 4;

            /* Write header length. */
            ret = store16(context, id, fcc_flen);
            if (ret)
                goto done;

            if (os_ctx->os_flags & KRB5_OS_TOFFSET_VALID) {
                /* Write time offset tag. */
                fcc_tag = FCC_TAG_DELTATIME;
                fcc_taglen = 2 * 4;

                ret = store16(context, id, fcc_tag);
                if (ret)
                    goto done;
                ret = store16(context, id, fcc_taglen);
                if (ret)
                    goto done;
                ret = store32(context, id, os_ctx->time_offset);
                if (ret)
                    goto done;
                ret = store32(context, id, os_ctx->usec_offset);
                if (ret)
                    goto done;
            }
        }
        invalidate_cache(data);
        goto done;
    }

    /* Verify a valid version number is there. */
    invalidate_cache(data);
    if (read(f, fcc_fvno, 2) != 2) {
        ret = KRB5_CC_FORMAT;
        goto done;
    }
    data->version = load_16_be(fcc_fvno);
    if (data->version != FVNO_4 && data->version != FVNO_3 &&
        data->version != FVNO_2 && data->version != FVNO_1) {
        ret = KRB5_CCACHE_BADVNO;
        goto done;
    }

    data->fd = f;

    if (data->version == FVNO_4) {
        if (read16(context, id, &fcc_flen) || fcc_flen > sizeof(buf)) {
            ret = KRB5_CC_FORMAT;
            goto done;
        }

        while (fcc_flen) {
            if (fcc_flen < 2 * 2 || read16(context, id, &fcc_tag) ||
                read16(context, id, &fcc_taglen) ||
                fcc_taglen > fcc_flen - 2 * 2) {
                ret = KRB5_CC_FORMAT;
                goto done;
            }

            switch (fcc_tag) {
            case FCC_TAG_DELTATIME:
                if (fcc_taglen != 2 * 4) {
                    ret = KRB5_CC_FORMAT;
                    goto done;
                }
                if (!(context->library_options & KRB5_LIBOPT_SYNC_KDCTIME) ||
                    (os_ctx->os_flags & KRB5_OS_TOFFSET_VALID)) {
                    if (read_bytes(context, id, buf, fcc_taglen)) {
                        ret = KRB5_CC_FORMAT;
                        goto done;
                    }
                    break;
                }
                if (read32(context, id, &time_offset) ||
                    read32(context, id, &usec_offset)) {
                    ret = KRB5_CC_FORMAT;
                    goto done;
                }
                os_ctx->time_offset = time_offset;
                os_ctx->usec_offset = usec_offset;
                os_ctx->os_flags =
                    ((os_ctx->os_flags & ~KRB5_OS_TOFFSET_TIME) |
                     KRB5_OS_TOFFSET_VALID);
                break;
            default:
                if (fcc_taglen && read_bytes(context, id, buf, fcc_taglen)) {
                    ret = KRB5_CC_FORMAT;
                    goto done;
                }
                break;
            }
            fcc_flen -= (2 * 2 + fcc_taglen);
        }
    }

done:
    if (ret) {
        data->fd = -1;
        (void)krb5_unlock_file(context, f);
        (void)close(f);
    }
    return ret;
}

/* Seek past the header in the cache file. */
static krb5_error_code
skip_header(krb5_context context, krb5_ccache id)
{
    fcc_data *data = id->data;
    krb5_error_code ret;
    uint16_t fcc_flen;

    k5_cc_mutex_assert_locked(context, &data->lock);

    fcc_lseek(data, 2, SEEK_SET);
    if (version(id) >= 4) {
        ret = read16(context, id, &fcc_flen);
        if (ret)
            return ret;
        if (fcc_lseek(data, fcc_flen, SEEK_CUR) < 0)
            return errno;
    }
    return 0;
}

/* Seek past the default principal in the cache file. */
static krb5_error_code
skip_principal(krb5_context context, krb5_ccache id)
{
    krb5_error_code ret;
    krb5_principal princ;

    k5_cc_mutex_assert_locked(context, &((fcc_data *)id->data)->lock);

    ret = read_principal(context, id, &princ);
    if (ret)
        return ret;

    krb5_free_principal(context, princ);
    return 0;
}

/* Create or overwrite the cache file with a header and default principal. */
static krb5_error_code KRB5_CALLCONV
fcc_initialize(krb5_context context, krb5_ccache id, krb5_principal princ)
{
    krb5_error_code ret;
    fcc_data *data = id->data;
    int st = 0;

    k5_cc_mutex_lock(context, &data->lock);

    MAYBE_OPEN(context, id, FCC_OPEN_AND_ERASE);

#if defined(HAVE_FCHMOD) || defined(HAVE_CHMOD)
#ifdef HAVE_FCHMOD
    st = fchmod(data->fd, S_IRUSR | S_IWUSR);
#else
    st = chmod(data->filename, S_IRUSR | S_IWUSR);
#endif
    if (st == -1) {
        ret = interpret_errno(context, errno);
        MAYBE_CLOSE(context, id, ret);
        k5_cc_mutex_unlock(context, &data->lock);
        return ret;
    }
#endif
    ret = store_principal(context, id, princ);

    MAYBE_CLOSE(context, id, ret);
    k5_cc_mutex_unlock(context, &data->lock);
    krb5_change_cache();
    return ret;
}

/* Drop the ref count.  If it hits zero, remove the entry from the fcc_set list
 * and free it. */
static krb5_error_code dereference(krb5_context context, fcc_data *data)
{
    struct fcc_set **fccsp, *temp;

    k5_cc_mutex_lock(context, &krb5int_cc_file_mutex);
    for (fccsp = &fccs; *fccsp != NULL; fccsp = &(*fccsp)->next) {
        if ((*fccsp)->data == data)
            break;
    }
    assert(*fccsp != NULL);
    assert((*fccsp)->data == data);
    (*fccsp)->refcount--;
    if ((*fccsp)->refcount == 0) {
        data = (*fccsp)->data;
        temp = *fccsp;
        *fccsp = (*fccsp)->next;
        free(temp);
        k5_cc_mutex_unlock(context, &krb5int_cc_file_mutex);
        k5_cc_mutex_assert_unlocked(context, &data->lock);
        free(data->filename);
        zap(data->buf, sizeof(data->buf));
        if (data->fd >= 0) {
            k5_cc_mutex_lock(context, &data->lock);
            close_cache_file(context, data);
            k5_cc_mutex_unlock(context, &data->lock);
        }
        k5_cc_mutex_destroy(&data->lock);
        free(data);
    } else {
        k5_cc_mutex_unlock(context, &krb5int_cc_file_mutex);
    }
    return 0;
}

/* Release the ccache handle. */
static krb5_error_code KRB5_CALLCONV
fcc_close(krb5_context context, krb5_ccache id)
{
    dereference(context, id->data);
    free(id);
    return 0;
}

/* Destroy the cache file and release the handle. */
static krb5_error_code KRB5_CALLCONV
fcc_destroy(krb5_context context, krb5_ccache id)
{
    krb5_error_code ret = 0;
    fcc_data *data = id->data;
    int st, fd;
    struct stat buf;
    unsigned long i, size;
    unsigned int wlen;
    char zeros[BUFSIZ];

    k5_cc_mutex_lock(context, &data->lock);

    if (OPENCLOSE(id)) {
        invalidate_cache(data);
        fd = THREEPARAMOPEN(data->filename, O_RDWR | O_BINARY, 0);
        if (fd < 0) {
            ret = interpret_errno(context, errno);
            goto cleanup;
        }
        set_cloexec_fd(fd);
        data->fd = fd;
    } else {
        fcc_lseek(data, 0, SEEK_SET);
    }

#ifdef MSDOS_FILESYSTEM
    /*
     * "Disgusting bit of UNIX trivia" - that's how the writers of NFS describe
     * the ability of UNIX to still write to a file which has been unlinked.
     * Naturally, the PC can't do this.  As a result, we have to delete the
     * file after we wipe it clean, but that throws off all the error handling
     * code.  So we have do the work ourselves.
     */
    st = fstat(data->fd, &buf);
    if (st == -1) {
        ret = interpret_errno(context, errno);
        size = 0;               /* Nothing to wipe clean */
    } else {
        size = (unsigned long)buf.st_size;
    }

    memset(zeros, 0, BUFSIZ);
    while (size > 0) {
        wlen = (int)((size > BUFSIZ) ? BUFSIZ : size); /* How much to write */
        i = write(data->fd, zeros, wlen);
        if (i < 0) {
            ret = interpret_errno(context, errno);
            /* Don't jump to cleanup--we still want to delete the file. */
            break;
        }
        size -= i;
    }

    if (OPENCLOSE(id)) {
        (void)close(((fcc_data *)id->data)->fd);
        data->fd = -1;
    }

    st = unlink(data->filename);
    if (st < 0) {
        ret = interpret_errno(context, errno);
        goto cleanup;
    }

#else /* MSDOS_FILESYSTEM */

    st = unlink(data->filename);
    if (st < 0) {
        ret = interpret_errno(context, errno);
        if (OPENCLOSE(id)) {
            (void)close(data->fd);
            data->fd = -1;
        }
        goto cleanup;
    }

    st = fstat(data->fd, &buf);
    if (st < 0) {
        ret = interpret_errno(context, errno);
        if (OPENCLOSE(id)) {
            (void)close(data->fd);
            data->fd = -1;
        }
        goto cleanup;
    }

    /* XXX This may not be legal XXX */
    size = (unsigned long)buf.st_size;
    memset(zeros, 0, BUFSIZ);
    for (i = 0; i < size / BUFSIZ; i++) {
        if (write(data->fd, zeros, BUFSIZ) < 0) {
            ret = interpret_errno(context, errno);
            if (OPENCLOSE(id)) {
                (void)close(data->fd);
                data->fd = -1;
            }
            goto cleanup;
        }
    }

    wlen = size % BUFSIZ;
    if (write(data->fd, zeros, wlen) < 0) {
        ret = interpret_errno(context, errno);
        if (OPENCLOSE(id)) {
            (void)close(data->fd);
            data->fd = -1;
        }
        goto cleanup;
    }

    st = close(data->fd);
    data->fd = -1;

    if (st)
        ret = interpret_errno(context, errno);

#endif /* MSDOS_FILESYSTEM */

cleanup:
    k5_cc_mutex_unlock(context, &data->lock);
    dereference(context, data);
    free(id);

    krb5_change_cache();
    return ret;
}

extern const krb5_cc_ops krb5_fcc_ops;

/* Create a file ccache handle for the pathname given by residual. */
static krb5_error_code KRB5_CALLCONV
fcc_resolve(krb5_context context, krb5_ccache *id, const char *residual)
{
    krb5_ccache lid;
    krb5_error_code ret;
    fcc_data *data;
    struct fcc_set *setptr;

    k5_cc_mutex_lock(context, &krb5int_cc_file_mutex);
    for (setptr = fccs; setptr; setptr = setptr->next) {
        if (!strcmp(setptr->data->filename, residual))
            break;
    }
    if (setptr) {
        data = setptr->data;
        assert(setptr->refcount != 0);
        setptr->refcount++;
        assert(setptr->refcount != 0);
        k5_cc_mutex_lock(context, &data->lock);
        k5_cc_mutex_unlock(context, &krb5int_cc_file_mutex);
    } else {
        data = malloc(sizeof(fcc_data));
        if (data == NULL) {
            k5_cc_mutex_unlock(context, &krb5int_cc_file_mutex);
            return KRB5_CC_NOMEM;
        }
        data->filename = strdup(residual);
        if (data->filename == NULL) {
            k5_cc_mutex_unlock(context, &krb5int_cc_file_mutex);
            free(data);
            return KRB5_CC_NOMEM;
        }
        ret = k5_cc_mutex_init(&data->lock);
        if (ret) {
            k5_cc_mutex_unlock(context, &krb5int_cc_file_mutex);
            free(data->filename);
            free(data);
            return ret;
        }
        k5_cc_mutex_lock(context, &data->lock);
        /* data->version,mode filled in for real later */
        data->version = data->mode = 0;
        data->flags = KRB5_TC_OPENCLOSE;
        data->fd = -1;
        data->valid_bytes = 0;
        setptr = malloc(sizeof(struct fcc_set));
        if (setptr == NULL) {
            k5_cc_mutex_unlock(context, &krb5int_cc_file_mutex);
            k5_cc_mutex_unlock(context, &data->lock);
            k5_cc_mutex_destroy(&data->lock);
            free(data->filename);
            free(data);
            return KRB5_CC_NOMEM;
        }
        setptr->refcount = 1;
        setptr->data = data;
        setptr->next = fccs;
        fccs = setptr;
        k5_cc_mutex_unlock(context, &krb5int_cc_file_mutex);
    }

    k5_cc_mutex_assert_locked(context, &data->lock);
    k5_cc_mutex_unlock(context, &data->lock);
    lid = malloc(sizeof(struct _krb5_ccache));
    if (lid == NULL) {
        dereference(context, data);
        return KRB5_CC_NOMEM;
    }

    lid->ops = &krb5_fcc_ops;
    lid->data = data;
    lid->magic = KV5M_CCACHE;

    /* Other routines will get errors on open, and callers must expect them, if
     * cache is non-existent/unusable. */
    *id = lid;
    return 0;
}

/* Prepare for a sequential iteration over the cache file. */
static krb5_error_code KRB5_CALLCONV
fcc_start_seq_get(krb5_context context, krb5_ccache id, krb5_cc_cursor *cursor)
{
    krb5_fcc_cursor *fcursor;
    krb5_error_code ret;
    fcc_data *data = id->data;

    k5_cc_mutex_lock(context, &data->lock);

    fcursor = malloc(sizeof(krb5_fcc_cursor));
    if (fcursor == NULL) {
        k5_cc_mutex_unlock(context, &data->lock);
        return KRB5_CC_NOMEM;
    }
    if (OPENCLOSE(id)) {
        ret = open_cache_file(context, id, FCC_OPEN_RDONLY);
        if (ret) {
            free(fcursor);
            k5_cc_mutex_unlock(context, &data->lock);
            return ret;
        }
    }

    /* Make sure we start reading right after the primary principal */
    ret = skip_header(context, id);
    if (ret) {
        free(fcursor);
        goto done;
    }
    ret = skip_principal(context, id);
    if (ret) {
        free(fcursor);
        goto done;
    }

    fcursor->pos = fcc_lseek(data, 0, SEEK_CUR);
    *cursor = (krb5_cc_cursor)fcursor;

done:
    MAYBE_CLOSE(context, id, ret);
    k5_cc_mutex_unlock(context, &data->lock);
    return ret;
}

/* Get the next credential from the cache file. */
static krb5_error_code KRB5_CALLCONV
fcc_next_cred(krb5_context context, krb5_ccache id, krb5_cc_cursor *cursor,
              krb5_creds *creds)
{
#define TCHECK(ret) if (ret) goto lose;
    krb5_error_code ret;
    krb5_fcc_cursor *fcursor = *cursor;
    int32_t int32;
    unsigned char octet;
    fcc_data *data = id->data;

    memset(creds, 0, sizeof(*creds));
    k5_cc_mutex_lock(context, &data->lock);
    MAYBE_OPEN(context, id, FCC_OPEN_RDONLY);

    if (fcc_lseek(data, fcursor->pos, SEEK_SET) == -1) {
        ret = interpret_errno(context, errno);
        goto lose;
    }

    ret = read_principal(context, id, &creds->client);
    TCHECK(ret);
    ret = read_principal(context, id, &creds->server);
    TCHECK(ret);
    ret = read_keyblock(context, id, &creds->keyblock);
    TCHECK(ret);
    ret = read_times(context, id, &creds->times);
    TCHECK(ret);
    ret = read_octet(context, id, &octet);
    TCHECK(ret);
    creds->is_skey = octet;
    ret = read32(context, id, &int32);
    TCHECK(ret);
    creds->ticket_flags = int32;
    ret = read_addrs(context, id, &creds->addresses);
    TCHECK(ret);
    ret = read_authdata(context, id, &creds->authdata);
    TCHECK(ret);
    ret = read_data(context, id, &creds->ticket);
    TCHECK(ret);
    ret = read_data(context, id, &creds->second_ticket);
    TCHECK(ret);

    fcursor->pos = fcc_lseek(data, 0, SEEK_CUR);

lose:
    MAYBE_CLOSE(context, id, ret);
    k5_cc_mutex_unlock(context, &data->lock);
    if (ret)
        krb5_free_cred_contents(context, creds);
    return ret;
}

/* Release an iteration cursor. */
static krb5_error_code KRB5_CALLCONV
fcc_end_seq_get(krb5_context context, krb5_ccache id, krb5_cc_cursor *cursor)
{
    /* We don't do anything with the file cache itself, so no need to lock
     * anything.  */
    free(*cursor);
    return 0;
}

/* Generate a unique file ccache using the given template (which will be
 * modified to contain the actual name of the file). */
krb5_error_code
krb5int_fcc_new_unique(krb5_context context, char *template, krb5_ccache *id)
{
    krb5_ccache lid;
    int fd;
    krb5_error_code ret;
    fcc_data *data;
    char fcc_fvno[2];
    int16_t fcc_flen = 0;
    int errsave, cnt;
    struct fcc_set *setptr;

    /* Set master lock */
    k5_cc_mutex_lock(context, &krb5int_cc_file_mutex);

    fd = mkstemp(template);
    if (fd == -1) {
        k5_cc_mutex_unlock(context, &krb5int_cc_file_mutex);
        return interpret_errno(context, errno);
    }
    set_cloexec_fd(fd);

    /* Allocate memory */
    data = malloc(sizeof(fcc_data));
    if (data == NULL) {
        k5_cc_mutex_unlock(context, &krb5int_cc_file_mutex);
        close(fd);
        unlink(template);
        return KRB5_CC_NOMEM;
    }

    data->filename = strdup(template);
    if (data->filename == NULL) {
        k5_cc_mutex_unlock(context, &krb5int_cc_file_mutex);
        free(data);
        close(fd);
        unlink(template);
        return KRB5_CC_NOMEM;
    }

    ret = k5_cc_mutex_init(&data->lock);
    if (ret) {
        k5_cc_mutex_unlock(context, &krb5int_cc_file_mutex);
        free(data->filename);
        free(data);
        close(fd);
        unlink(template);
        return ret;
    }
    k5_cc_mutex_lock(context, &data->lock);

    /*
     * The file is initially closed at the end of this call...
     */
    data->flags = 0;
    data->fd = -1;
    data->valid_bytes = 0;
    /* data->version,mode filled in for real later */
    data->version = data->mode = 0;

    /* Ignore user's umask, set mode = 0600 */
#ifndef HAVE_FCHMOD
#ifdef HAVE_CHMOD
    chmod(data->filename, S_IRUSR | S_IWUSR);
#endif
#else
    fchmod(fd, S_IRUSR | S_IWUSR);
#endif
    store_16_be(context->fcc_default_format, fcc_fvno);
    cnt = write(fd, &fcc_fvno, 2);
    if (cnt != 2) {
        errsave = errno;
        (void)close(fd);
        (void)unlink(data->filename);
        ret = (cnt == -1) ? interpret_errno(context, errsave) : KRB5_CC_IO;
        goto err_out;
    }
    /* For version 4 we save a length for the rest of the header */
    if (context->fcc_default_format == FVNO_4) {
        cnt = write(fd, &fcc_flen, sizeof(fcc_flen));
        if (cnt != sizeof(fcc_flen)) {
            errsave = errno;
            (void)close(fd);
            (void)unlink(data->filename);
            ret = (cnt == -1) ? interpret_errno(context, errsave) : KRB5_CC_IO;
            goto err_out;
        }
    }
    if (close(fd) == -1) {
        errsave = errno;
        (void)unlink(data->filename);
        ret = interpret_errno(context, errsave);
        goto err_out;
    }

    setptr = malloc(sizeof(struct fcc_set));
    if (setptr == NULL) {
        k5_cc_mutex_unlock(context, &krb5int_cc_file_mutex);
        k5_cc_mutex_unlock(context, &data->lock);
        k5_cc_mutex_destroy(&data->lock);
        free(data->filename);
        free(data);
        (void)unlink(template);
        return KRB5_CC_NOMEM;
    }
    setptr->refcount = 1;
    setptr->data = data;
    setptr->next = fccs;
    fccs = setptr;
    k5_cc_mutex_unlock(context, &krb5int_cc_file_mutex);

    k5_cc_mutex_assert_locked(context, &data->lock);
    k5_cc_mutex_unlock(context, &data->lock);
    lid = malloc(sizeof(*lid));
    if (lid == NULL) {
        dereference(context, data);
        return KRB5_CC_NOMEM;
    }

    lid->ops = &krb5_fcc_ops;
    lid->data = data;
    lid->magic = KV5M_CCACHE;

    /* Default to open/close on every call. */
    data->flags = KRB5_TC_OPENCLOSE;

    *id = lid;

    krb5_change_cache();
    return 0;

err_out:
    k5_cc_mutex_unlock(context, &krb5int_cc_file_mutex);
    k5_cc_mutex_unlock(context, &data->lock);
    k5_cc_mutex_destroy(&data->lock);
    free(data->filename);
    free(data);
    return ret;
}

/*
 * Create a new file cred cache whose name is guaranteed to be unique.  The
 * name begins with the string TKT_ROOT (from fcc.h).  The cache file is not
 * opened, but the new filename is reserved.
 */
static krb5_error_code KRB5_CALLCONV
fcc_generate_new(krb5_context context, krb5_ccache *id)
{
    char scratch[sizeof(TKT_ROOT) + 7]; /* Room for XXXXXX and terminator */

    (void)snprintf(scratch, sizeof(scratch), "%sXXXXXX", TKT_ROOT);
    return krb5int_fcc_new_unique(context, scratch, id);
}

/* Return an alias to the pathname of the cache file. */
static const char * KRB5_CALLCONV
fcc_get_name(krb5_context context, krb5_ccache id)
{
    return ((fcc_data *)id->data)->filename;
}

/* Retrieve a copy of the default principal, if the cache is initialized. */
static krb5_error_code KRB5_CALLCONV
fcc_get_principal(krb5_context context, krb5_ccache id, krb5_principal *princ)
{
    krb5_error_code ret;

    k5_cc_mutex_lock(context, &((fcc_data *)id->data)->lock);

    MAYBE_OPEN(context, id, FCC_OPEN_RDONLY);

    /* make sure we're beyond the header */
    ret = skip_header(context, id);
    if (ret)
        goto done;
    ret = read_principal(context, id, princ);

done:
    MAYBE_CLOSE(context, id, ret);
    k5_cc_mutex_unlock(context, &((fcc_data *)id->data)->lock);
    return ret;
}

/* Search for a credential within the cache file. */
static krb5_error_code KRB5_CALLCONV
fcc_retrieve(krb5_context context, krb5_ccache id, krb5_flags whichfields,
             krb5_creds *mcreds, krb5_creds *creds)
{
    return k5_cc_retrieve_cred_default(context, id, whichfields, mcreds,
                                       creds);
}

/* Store a credential in the cache file. */
static krb5_error_code KRB5_CALLCONV
fcc_store(krb5_context context, krb5_ccache id, krb5_creds *creds)
{
#define TCHECK(ret) if (ret) goto lose;
    krb5_error_code ret;

    k5_cc_mutex_lock(context, &((fcc_data *)id->data)->lock);

    /* Make sure we are writing to the end of the file */
    MAYBE_OPEN(context, id, FCC_OPEN_RDWR);

    /* Make sure we are writing to the end of the file */
    ret = fcc_lseek(id->data, 0, SEEK_END);
    if (ret < 0) {
        if (OPENCLOSE(id))
            (void)close_cache_file(context, id->data);
        k5_cc_mutex_unlock(context, &((fcc_data *)id->data)->lock);
        return interpret_errno(context, errno);
    }

    ret = store_principal(context, id, creds->client);
    TCHECK(ret);
    ret = store_principal(context, id, creds->server);
    TCHECK(ret);
    ret = store_keyblock(context, id, &creds->keyblock);
    TCHECK(ret);
    ret = store_times(context, id, &creds->times);
    TCHECK(ret);
    ret = store_octet(context, id, creds->is_skey);
    TCHECK(ret);
    ret = store32(context, id, creds->ticket_flags);
    TCHECK(ret);
    ret = store_addrs(context, id, creds->addresses);
    TCHECK(ret);
    ret = store_authdata(context, id, creds->authdata);
    TCHECK(ret);
    ret = store_data(context, id, &creds->ticket);
    TCHECK(ret);
    ret = store_data(context, id, &creds->second_ticket);
    TCHECK(ret);

lose:
    MAYBE_CLOSE(context, id, ret);
    k5_cc_mutex_unlock(context, &((fcc_data *)id->data)->lock);
    krb5_change_cache();
    return ret;
#undef TCHECK
}

/* Non-functional stub for removing a cred from the cache file. */
static krb5_error_code KRB5_CALLCONV
fcc_remove_cred(krb5_context context, krb5_ccache cache, krb5_flags flags,
                krb5_creds *creds)
{
    return KRB5_CC_NOSUPP;
}

/* Set flags for the ccache.  Open the cache file if KRB5_TC_OPENCLOSE is
 * turned off, or close it if it is turned on. */
static krb5_error_code KRB5_CALLCONV
fcc_set_flags(krb5_context context, krb5_ccache id, krb5_flags flags)
{
    fcc_data *data = id->data;

    k5_cc_mutex_lock(context, &data->lock);

    if (flags & KRB5_TC_OPENCLOSE) {
        /* Asking to turn on OPENCLOSE mode. */
        if (!OPENCLOSE(id))
            (void)close_cache_file(context, data);
    } else {
        /* Asking to turn off OPENCLOSE mode, meaning it must be
         * left open.  We open if it's not yet open. */
        MAYBE_OPEN(context, id, FCC_OPEN_RDONLY);
    }

    data->flags = flags;
    k5_cc_mutex_unlock(context, &data->lock);
    return 0;
}

/* Get the current flags for the cache. */
static krb5_error_code KRB5_CALLCONV
fcc_get_flags(krb5_context context, krb5_ccache id, krb5_flags *flags)
{
    fcc_data *data = id->data;

    k5_cc_mutex_lock(context, &data->lock);
    *flags = data->flags;
    k5_cc_mutex_unlock(context, &data->lock);
    return 0;
}

/* Prepare to iterate over the caches in the per-type collection. */
static krb5_error_code KRB5_CALLCONV
fcc_ptcursor_new(krb5_context context, krb5_cc_ptcursor *cursor)
{
    krb5_cc_ptcursor n = NULL;
    struct krb5_fcc_ptcursor_data *cdata = NULL;

    *cursor = NULL;

    n = malloc(sizeof(*n));
    if (n == NULL)
        return ENOMEM;
    n->ops = &krb5_fcc_ops;
    cdata = malloc(sizeof(*cdata));
    if (cdata == NULL) {
        free(n);
        return ENOMEM;
    }
    cdata->first = TRUE;
    n->data = cdata;
    *cursor = n;
    return 0;
}

/* Get the next cache in the per-type collection.  The FILE per-type collection
 * contains only the context's default cache if it is a file cache. */
static krb5_error_code KRB5_CALLCONV
fcc_ptcursor_next(krb5_context context, krb5_cc_ptcursor cursor,
                  krb5_ccache *cache_out)
{
    krb5_error_code ret;
    struct krb5_fcc_ptcursor_data *cdata = cursor->data;
    const char *defname, *residual;
    krb5_ccache cache;
    struct stat sb;

    *cache_out = NULL;
    if (!cdata->first)
        return 0;
    cdata->first = FALSE;

    defname = krb5_cc_default_name(context);
    if (!defname)
        return 0;

    /* Check if the default has type FILE or no type; find the residual. */
    if (strncmp(defname, "FILE:", 5) == 0)
        residual = defname + 5;
    else if (strchr(defname + 2, ':') == NULL)  /* Skip drive prefix if any. */
        residual = defname;
    else
        return 0;

    /* Don't yield a nonexistent default file cache. */
    if (stat(residual, &sb) != 0)
        return 0;

    ret = krb5_cc_resolve(context, defname, &cache);
    if (ret)
        return ret;
    *cache_out = cache;
    return 0;
}

/* Release a per-type collection iteration cursor. */
static krb5_error_code KRB5_CALLCONV
fcc_ptcursor_free(krb5_context context, krb5_cc_ptcursor *cursor)
{
    if (*cursor == NULL)
        return 0;
    free((*cursor)->data);
    free(*cursor);
    *cursor = NULL;
    return 0;
}

/* Get the cache file's last modification time. */
static krb5_error_code KRB5_CALLCONV
fcc_last_change_time(krb5_context context, krb5_ccache id,
                     krb5_timestamp *change_time)
{
    krb5_error_code ret = 0;
    fcc_data *data = id->data;
    struct stat buf;

    *change_time = 0;

    k5_cc_mutex_lock(context, &data->lock);

    if (stat(data->filename, &buf) == -1)
        ret = interpret_errno(context, errno);
    else
        *change_time = (krb5_timestamp)buf.st_mtime;

    k5_cc_mutex_unlock(context, &data->lock);

    return ret;
}

/* Lock the cache handle against other threads.  (This does not lock the cache
 * file against other processes.) */
static krb5_error_code KRB5_CALLCONV
fcc_lock(krb5_context context, krb5_ccache id)
{
    fcc_data *data = id->data;
    k5_cc_mutex_lock(context, &data->lock);
    return 0;
}

/* Unlock the cache handle. */
static krb5_error_code KRB5_CALLCONV
fcc_unlock(krb5_context context, krb5_ccache id)
{
    fcc_data *data = id->data;
    k5_cc_mutex_unlock(context, &data->lock);
    return 0;
}

/* Translate a system errno value to a Kerberos com_err code. */
static krb5_error_code
interpret_errno(krb5_context context, int errnum)
{
    krb5_error_code ret;

    switch (errnum) {
    case ENOENT:
        ret = KRB5_FCC_NOFILE;
        break;
    case EPERM:
    case EACCES:
#ifdef EISDIR
    case EISDIR:                /* Mac doesn't have EISDIR */
#endif
    case ENOTDIR:
#ifdef ELOOP
    case ELOOP:                 /* Bad symlink is like no file. */
#endif
#ifdef ETXTBSY
    case ETXTBSY:
#endif
    case EBUSY:
    case EROFS:
        ret = KRB5_FCC_PERM;
        break;
    case EINVAL:
    case EEXIST:
    case EFAULT:
    case EBADF:
#ifdef ENAMETOOLONG
    case ENAMETOOLONG:
#endif
#ifdef EWOULDBLOCK
    case EWOULDBLOCK:
#endif
        ret = KRB5_FCC_INTERNAL;
        break;
#ifdef EDQUOT
    case EDQUOT:
#endif
    case ENOSPC:
    case EIO:
    case ENFILE:
    case EMFILE:
    case ENXIO:
    default:
        ret = KRB5_CC_IO;
        krb5_set_error_message(context, ret,
                               _("Credentials cache I/O operation failed "
                                 "(%s)"), strerror(errnum));
    }
    return ret;
}

const krb5_cc_ops krb5_fcc_ops = {
    0,
    "FILE",
    fcc_get_name,
    fcc_resolve,
    fcc_generate_new,
    fcc_initialize,
    fcc_destroy,
    fcc_close,
    fcc_store,
    fcc_retrieve,
    fcc_get_principal,
    fcc_start_seq_get,
    fcc_next_cred,
    fcc_end_seq_get,
    fcc_remove_cred,
    fcc_set_flags,
    fcc_get_flags,
    fcc_ptcursor_new,
    fcc_ptcursor_next,
    fcc_ptcursor_free,
    NULL, /* move */
    fcc_last_change_time,
    NULL, /* wasdefault */
    fcc_lock,
    fcc_unlock,
    NULL, /* switch_to */
};

#if defined(_WIN32)
/*
 * krb5_change_cache should be called after the cache changes.
 * A notification message is is posted out to all top level
 * windows so that they may recheck the cache based on the
 * changes made.  We register a unique message type with which
 * we'll communicate to all other processes.
 */

krb5_error_code
krb5_change_cache(void)
{
    PostMessage(HWND_BROADCAST, krb5_get_notification_message(), 0, 0);
    return 0;
}

unsigned int KRB5_CALLCONV
krb5_get_notification_message(void)
{
    static unsigned int message = 0;

    if (message == 0)
        message = RegisterWindowMessage(WM_KERBEROS5_CHANGED);

    return message;
}
#else /* _WIN32 */

krb5_error_code
krb5_change_cache(void)
{
    return 0;
}

unsigned int
krb5_get_notification_message(void)
{
    return 0;
}

#endif /* _WIN32 */

const krb5_cc_ops krb5_cc_file_ops = {
    0,
    "FILE",
    fcc_get_name,
    fcc_resolve,
    fcc_generate_new,
    fcc_initialize,
    fcc_destroy,
    fcc_close,
    fcc_store,
    fcc_retrieve,
    fcc_get_principal,
    fcc_start_seq_get,
    fcc_next_cred,
    fcc_end_seq_get,
    fcc_remove_cred,
    fcc_set_flags,
    fcc_get_flags,
    fcc_ptcursor_new,
    fcc_ptcursor_next,
    fcc_ptcursor_free,
    NULL, /* move */
    fcc_last_change_time,
    NULL, /* wasdefault */
    fcc_lock,
    fcc_unlock,
    NULL, /* switch_to */
};
