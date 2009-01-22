/* -*- mode: c; indent-tabs-mode: nil -*- */

/*
 * t_k5buf.c
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
 * Test the k5buf string buffer module.
 */

#include "k5buf-int.h"
#include <stdio.h>
#include <stdlib.h>

static void fail_if(int condition, const char *name)
{
    if (condition) {
        fprintf(stderr, "%s failed\n", name);
        exit(1);
    }
}

/* Test the invariants of a buffer. */
static void check_buf(struct k5buf *buf, const char *name)
{
    fail_if(buf->buftype != FIXED && buf->buftype != DYNAMIC
            && buf->buftype != ERROR, name);
    if (buf->buftype == ERROR)
        return;
    fail_if(buf->space == 0, name);
    fail_if(buf->space > SPACE_MAX, name);
    fail_if(buf->len >= buf->space, name);
    fail_if(buf->data[buf->len] != 0, name);
}

static void test_basic()
{
    struct k5buf buf;
    char storage[1024], *s;
    ssize_t len;

    krb5int_buf_init_fixed(&buf, storage, sizeof(storage));
    krb5int_buf_add(&buf, "Hello ");
    krb5int_buf_add_len(&buf, "world", 5);
    check_buf(&buf, "basic fixed");
    s = krb5int_buf_data(&buf);
    len = krb5int_buf_len(&buf);
    fail_if(!s || strcmp(s, "Hello world") != 0 || len != 11, "basic fixed");

    krb5int_buf_init_dynamic(&buf);
    krb5int_buf_add_len(&buf, "Hello", 5);
    krb5int_buf_add(&buf, " world");
    check_buf(&buf, "basic dynamic");
    s = krb5int_buf_data(&buf);
    len = krb5int_buf_len(&buf);
    fail_if(!s || strcmp(s, "Hello world") != 0 || len != 11, "basic dynamic");
    krb5int_free_buf(&buf);
}

static void test_realloc()
{
    struct k5buf buf;
    char data[1024], *s;
    ssize_t len;
    size_t i;

    for (i = 0; i < sizeof(data); i++)
        data[i] = 'a';

    /* Cause the buffer size to double from 128 to 256 bytes. */
    krb5int_buf_init_dynamic(&buf);
    krb5int_buf_add_len(&buf, data, 10);
    krb5int_buf_add_len(&buf, data, 128);
    fail_if(buf.space != 256, "realloc 1");
    check_buf(&buf, "realloc 1");
    s = krb5int_buf_data(&buf);
    len = krb5int_buf_len(&buf);
    fail_if(!s || len != 138 || memcmp(s, data, len) != 0, "realloc 1");

    /* Cause the same buffer to double in size to 512 bytes. */
    krb5int_buf_add_len(&buf, data, 128);
    fail_if(buf.space != 512, "realloc 2");
    check_buf(&buf, "realloc 2");
    s = krb5int_buf_data(&buf);
    len = krb5int_buf_len(&buf);
    fail_if(!s || len != 266 || memcmp(s, data, len) != 0, "realloc 2");
    krb5int_free_buf(&buf);

    /* Cause a buffer to increase from 128 to 512 bytes directly. */
    krb5int_buf_init_dynamic(&buf);
    krb5int_buf_add_len(&buf, data, 10);
    krb5int_buf_add_len(&buf, data, 256);
    fail_if(buf.space != 512, "realloc 3");
    check_buf(&buf, "realloc 3");
    s = krb5int_buf_data(&buf);
    len = krb5int_buf_len(&buf);
    fail_if(!s || len != 266 || memcmp(s, data, len) != 0, "realloc 3");
    krb5int_free_buf(&buf);

    /* Cause a buffer to increase from 128 to 1024 bytes directly. */
    krb5int_buf_init_dynamic(&buf);
    krb5int_buf_add_len(&buf, data, 10);
    krb5int_buf_add_len(&buf, data, 512);
    fail_if(buf.space != 1024, "realloc 4");
    check_buf(&buf, "realloc 4");
    s = krb5int_buf_data(&buf);
    len = krb5int_buf_len(&buf);
    fail_if(!s || len != 522 || memcmp(s, data, len) != 0, "realloc 4");
    krb5int_free_buf(&buf);

    /* Cause a reallocation to fail by exceeding SPACE_MAX. */
    krb5int_buf_init_dynamic(&buf);
    krb5int_buf_add_len(&buf, data, 10);
    krb5int_buf_add_len(&buf, NULL, SPACE_MAX);
    check_buf(&buf, "realloc 5");
    s = krb5int_buf_data(&buf);
    len = krb5int_buf_len(&buf);
    fail_if(buf.buftype != ERROR || s != NULL || len != -1, "realloc 5");
    krb5int_free_buf(&buf);

    /* Cause a reallocation to fail by integer overflow. */
    krb5int_buf_init_dynamic(&buf);
    krb5int_buf_add_len(&buf, data, 100);
    krb5int_buf_add_len(&buf, NULL, SPACE_MAX * 2);
    check_buf(&buf, "realloc 6");
    s = krb5int_buf_data(&buf);
    len = krb5int_buf_len(&buf);
    fail_if(buf.buftype != ERROR || s != NULL || len != -1, "realloc 6");
    krb5int_free_buf(&buf);
}

static void test_overflow()
{
    struct k5buf buf;
    char storage[10], *s;
    ssize_t len;

    /* Cause a fixed-sized buffer overflow. */
    krb5int_buf_init_fixed(&buf, storage, sizeof(storage));
    krb5int_buf_add(&buf, "12345");
    krb5int_buf_add(&buf, "12345");
    check_buf(&buf, "overflow 1");
    s = krb5int_buf_data(&buf);
    len = krb5int_buf_len(&buf);
    fail_if(buf.buftype != ERROR || s != NULL || len != -1, "overflow 1");

    /* Cause a fixed-sized buffer overflow with integer overflow. */
    krb5int_buf_init_fixed(&buf, storage, sizeof(storage));
    krb5int_buf_add(&buf, "12345");
    krb5int_buf_add_len(&buf, NULL, SPACE_MAX * 2);
    check_buf(&buf, "overflow 2");
    s = krb5int_buf_data(&buf);
    len = krb5int_buf_len(&buf);
    fail_if(buf.buftype != ERROR || s != NULL || len != -1, "overflow 2");
}

static void test_error()
{
    struct k5buf buf;
    char storage[1];

    /* Cause an overflow and then perform actions afterwards. */
    krb5int_buf_init_fixed(&buf, storage, sizeof(storage));
    krb5int_buf_add(&buf, "1");
    fail_if(buf.buftype != ERROR, "error");
    check_buf(&buf, "error");
    krb5int_buf_add(&buf, "test");
    check_buf(&buf, "error");
    krb5int_buf_add_len(&buf, "test", 4);
    check_buf(&buf, "error");
    krb5int_buf_truncate(&buf, 3);
    check_buf(&buf, "error");
    fail_if(buf.buftype != ERROR, "error");
}

static void test_truncate()
{
    struct k5buf buf;
    char *s;
    ssize_t len;

    krb5int_buf_init_dynamic(&buf);
    krb5int_buf_add(&buf, "abcde");
    krb5int_buf_add(&buf, "fghij");
    krb5int_buf_truncate(&buf, 7);
    check_buf(&buf, "truncate");
    s = krb5int_buf_data(&buf);
    len = krb5int_buf_len(&buf);
    fail_if(!s || len != 7 || strcmp(s, "abcdefg") != 0, "truncate");
    krb5int_free_buf(&buf);
}

static void test_binary()
{
    struct k5buf buf;
    char *s, data[] = { 'a', 0, 'b' };
    ssize_t len;

    krb5int_buf_init_dynamic(&buf);
    krb5int_buf_add_len(&buf, data, 3);
    krb5int_buf_add_len(&buf, data, 3);
    check_buf(&buf, "binary");
    s = krb5int_buf_data(&buf);
    len = krb5int_buf_len(&buf);
    fail_if(!s || len != 6, "binary");
    fail_if(s[0] != 'a' || s[1] != 0 || s[2] != 'b', "binary");
    fail_if(s[3] != 'a' || s[4] != 0 || s[5] != 'b', "binary");
    krb5int_free_buf(&buf);
}

static void test_fmt()
{
    struct k5buf buf;
    char *s, storage[10], data[1024];
    ssize_t len;
    size_t i;

    for (i = 0; i < sizeof(data) - 1; i++)
        data[i] = 'a';
    data[i] = '\0';

    /* Format some text into a non-empty fixed buffer. */
    krb5int_buf_init_fixed(&buf, storage, sizeof(storage));
    krb5int_buf_add(&buf, "foo");
    krb5int_buf_add_fmt(&buf, " %d ", 3);
    check_buf(&buf, "fmt 1");
    s = krb5int_buf_data(&buf);
    len = krb5int_buf_len(&buf);
    fail_if(!s || len != 6 || strcmp(s, "foo 3 ") != 0, "fmt 1");

    /* Overflow the same buffer with formatted text. */
    krb5int_buf_add_fmt(&buf, "%d%d%d%d", 1, 2, 3, 4);
    check_buf(&buf, "fmt 2");
    s = krb5int_buf_data(&buf);
    len = krb5int_buf_len(&buf);
    fail_if(buf.buftype != ERROR || s != NULL || len != -1, "fmt 2");

    /* Format some text into a non-empty dynamic buffer. */
    krb5int_buf_init_dynamic(&buf);
    krb5int_buf_add(&buf, "foo");
    krb5int_buf_add_fmt(&buf, " %d ", 3);
    check_buf(&buf, "fmt 3");
    s = krb5int_buf_data(&buf);
    len = krb5int_buf_len(&buf);
    fail_if(!s || len != 6 || strcmp(s, "foo 3 ") != 0, "fmt 3");

    /* Format more text into the same buffer, causing a big resize. */
    krb5int_buf_add_fmt(&buf, "%s", data);
    check_buf(&buf, "fmt 4");
    fail_if(buf.space != 2048, "fmt 4");
    s = krb5int_buf_data(&buf);
    len = krb5int_buf_len(&buf);
    fail_if(!s || len != 1029 || strcmp(s + 6, data) != 0, "fmt 4");
    krb5int_free_buf(&buf);
}

int main()
{
    test_basic();
    test_realloc();
    test_overflow();
    test_error();
    test_truncate();
    test_binary();
    test_fmt();
    return 0;
}
