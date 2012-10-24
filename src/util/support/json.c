/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* util/support/json.c - JSON parser and unparser */
/*
 * Copyright (c) 2010 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Portions Copyright (c) 2010 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * Copyright (C) 2012 by the Massachusetts Institute of Technology.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * This file implements a minimal dynamic type system for JSON values and a
 * JSON encoder and decoder.  It is loosely based on the heimbase code from
 * Heimdal.
 */

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <k5-base64.h>
#include <k5-json.h>
#include <k5-buf.h>

#define MAX_DECODE_DEPTH 64

typedef void (*type_dealloc_fn)(void *val);

typedef struct json_type_st {
    k5_json_tid tid;
    const char *name;
    type_dealloc_fn dealloc;
} *json_type;

struct value_base {
    json_type isa;
    unsigned int ref_cnt;
};

#define PTR2BASE(ptr) (((struct value_base *)ptr) - 1)
#define BASE2PTR(ptr) ((void *)(((struct value_base *)ptr) + 1))

void *
k5_json_retain(k5_json_value val)
{
    struct value_base *p;

    if (val == NULL)
        return val;
    p = PTR2BASE(val);
    assert(p->ref_cnt != 0);
    p->ref_cnt++;
    return val;
}

void
k5_json_release(k5_json_value val)
{
    struct value_base *p;

    if (val == NULL)
        return;
    p = PTR2BASE(val);
    assert(p->ref_cnt != 0);
    p->ref_cnt--;
    if (p->ref_cnt == 0) {
        if (p->isa->dealloc != NULL)
            p->isa->dealloc(val);
        free(p);
    }
}

/* Get the type description of a k5_json_value. */
static json_type
get_isa(k5_json_value val)
{
    struct value_base *p = PTR2BASE(val);

    return p->isa;
}

k5_json_tid
k5_json_get_tid(k5_json_value val)
{
    json_type isa = get_isa(val);

    return isa->tid;
}

static k5_json_value
alloc_value(json_type type, size_t size)
{
    struct value_base *p = calloc(1, size + sizeof(*p));

    if (p == NULL)
        return NULL;
    p->isa = type;
    p->ref_cnt = 1;

    return BASE2PTR(p);
}

/*** Null type ***/

static struct json_type_st null_type = { K5_JSON_TID_NULL, "null", NULL };

k5_json_null
k5_json_null_create(void)
{
    return alloc_value(&null_type, 0);
}

/*** Boolean type ***/

static struct json_type_st bool_type = { K5_JSON_TID_BOOL, "bool", NULL };

k5_json_bool
k5_json_bool_create(int truth)
{
    k5_json_bool b;

    b = alloc_value(&bool_type, 1);
    *(unsigned char *)b = !!truth;
    return b;
}

int
k5_json_bool_value(k5_json_bool bval)
{
    return *(unsigned char *)bval;
}

/*** Array type ***/

struct k5_json_array_st {
    k5_json_value *values;
    size_t len;
    size_t allocated;
};

static void
array_dealloc(void *ptr)
{
    k5_json_array array = ptr;
    size_t i;

    for (i = 0; i < array->len; i++)
        k5_json_release(array->values[i]);
    free(array->values);
}

static struct json_type_st array_type = {
    K5_JSON_TID_ARRAY, "array", array_dealloc
};

k5_json_array
k5_json_array_create(void)
{
    return alloc_value(&array_type, sizeof(struct k5_json_array_st));
}

int
k5_json_array_add(k5_json_array array, k5_json_value val)
{
    k5_json_value *ptr;
    size_t new_alloc;

    if (array->len >= array->allocated) {
        /* Increase the number of slots by 50% (16 slots minimum). */
        new_alloc = array->len + 1 + (array->len >> 1);
        if (new_alloc < 16)
            new_alloc = 16;
        ptr = realloc(array->values, new_alloc * sizeof(*array->values));
        if (ptr == NULL)
            return ENOMEM;
        array->values = ptr;
        array->allocated = new_alloc;
    }
    array->values[array->len++] = k5_json_retain(val);
    return 0;
}

size_t
k5_json_array_length(k5_json_array array)
{
    return array->len;
}

k5_json_value
k5_json_array_get(k5_json_array array, size_t idx)
{
    if (idx >= array->len)
        abort();
    return array->values[idx];
}

void
k5_json_array_set(k5_json_array array, size_t idx, k5_json_value val)
{
    if (idx >= array->len)
        abort();
    k5_json_release(array->values[idx]);
    array->values[idx] = k5_json_retain(val);
}

/*** Object type (string:value mapping) ***/

struct entry {
    char *key;
    k5_json_value value;
};

struct k5_json_object_st {
    struct entry *entries;
    size_t len;
    size_t allocated;
};

static void
object_dealloc(void *ptr)
{
    k5_json_object obj = ptr;
    size_t i;

    for (i = 0; i < obj->len; i++) {
        free(obj->entries[i].key);
        k5_json_release(obj->entries[i].value);
    }
    free(obj->entries);
}

static struct json_type_st object_type = {
    K5_JSON_TID_OBJECT, "object", object_dealloc
};

k5_json_object
k5_json_object_create(void)
{
    return alloc_value(&object_type, sizeof(struct k5_json_object_st));
}

size_t
k5_json_object_count(k5_json_object obj)
{
    return obj->len;
}

/* Return the entry for key within obj, or NULL if none exists. */
static struct entry *
object_search(k5_json_object obj, const char *key)
{
    size_t i;

    for (i = 0; i < obj->len; i++) {
        if (strcmp(key, obj->entries[i].key) == 0)
            return &obj->entries[i];
    }
    return NULL;
}

k5_json_value
k5_json_object_get(k5_json_object obj, const char *key)
{
    struct entry *ent;

    ent = object_search(obj, key);
    if (ent == NULL)
        return NULL;
    return ent->value;
}

int
k5_json_object_set(k5_json_object obj, const char *key, k5_json_value val)
{
    struct entry *ent, *ptr;
    size_t new_alloc;

    ent = object_search(obj, key);
    if (ent) {
        k5_json_release(ent->value);
        ent->value = k5_json_retain(val);
        return 0;
    }

    if (obj->len >= obj->allocated) {
        /* Increase the number of slots by 50% (16 slots minimum). */
        new_alloc = obj->len + 1 + (obj->len >> 1);
        if (new_alloc < 16)
            new_alloc = 16;
        ptr = realloc(obj->entries, new_alloc * sizeof(*obj->entries));
        if (ptr == NULL)
            return ENOMEM;
        obj->entries = ptr;
        obj->allocated = new_alloc;
    }
    obj->entries[obj->len].key = strdup(key);
    if (obj->entries[obj->len].key == NULL)
        return ENOMEM;
    obj->entries[obj->len].value = k5_json_retain(val);
    obj->len++;
    return 0;
}

void
k5_json_object_iterate(k5_json_object obj, k5_json_object_iterator_fn func,
                       void *arg)
{
    size_t i;

    for (i = 0; i < obj->len; i++)
        func(arg, obj->entries[i].key, obj->entries[i].value);
}

/*** String type ***/

static struct json_type_st string_type = {
    K5_JSON_TID_STRING, "string", NULL
};

k5_json_string
k5_json_string_create(const char *string)
{
    return k5_json_string_create_len(string, strlen(string));
}

k5_json_string
k5_json_string_create_len(const void *data, size_t len)
{
    char *s;

    s = alloc_value(&string_type, len + 1);
    if (s == NULL)
        return NULL;
    memcpy(s, data, len);
    s[len] = '\0';
    return (k5_json_string)s;
}

k5_json_string
k5_json_string_create_base64(const void *data, size_t len)
{
    char *base64;
    k5_json_string s;

    base64 = k5_base64_encode(data, len);
    if (base64 == NULL)
        return NULL;
    s = k5_json_string_create(base64);
    free(base64);
    return s;
}

const char *
k5_json_string_utf8(k5_json_string string)
{
    return (const char *)string;
}

void *
k5_json_string_unbase64(k5_json_string string, size_t *len_out)
{
    return k5_base64_decode((const char *)string, len_out);
}

/*** Number type ***/

static struct json_type_st number_type = {
    K5_JSON_TID_NUMBER, "number", NULL
};

k5_json_number
k5_json_number_create(long long number)
{
    k5_json_number n;

    n = alloc_value(&number_type, sizeof(long long));
    if (n)
        *((long long *)n) = number;
    return n;
}

long long
k5_json_number_value(k5_json_number number)
{
    return *(long long *)number;
}

/*** JSON encoding ***/

static const char quotemap_json[] = "\"\\/bfnrt";
static const char quotemap_c[] = "\"\\/\b\f\n\r\t";
static const char needs_quote[] = "\\\"\1\2\3\4\5\6\7\10\11\12\13\14\15\16\17"
    "\20\21\22\23\24\25\26\27\30\31\32\33\34\35\36\37";

struct encode_ctx {
    struct k5buf buf;
    int ret;
    int first;
};

static int encode_value(struct encode_ctx *j, k5_json_value val);

static void
encode_string(struct encode_ctx *j, const char *str)
{
    size_t n;
    const char *p;

    krb5int_buf_add(&j->buf, "\"");
    while (*str != '\0') {
        n = strcspn(str, needs_quote);
        krb5int_buf_add_len(&j->buf, str, n);
        str += n;
        if (*str == '\0')
            break;
        krb5int_buf_add(&j->buf, "\\");
        p = strchr(quotemap_c, *str);
        if (p != NULL)
            krb5int_buf_add_len(&j->buf, quotemap_json + (p - quotemap_c), 1);
        else
            krb5int_buf_add_fmt(&j->buf, "u00%02X", (unsigned int)*str);
        str++;
    }
    krb5int_buf_add(&j->buf, "\"");
}

static void
encode_dict_entry(void *ctx, const char *key, k5_json_value value)
{
    struct encode_ctx *j = ctx;

    if (j->ret)
        return;
    if (j->first)
        j->first = 0;
    else
        krb5int_buf_add(&j->buf, ",");
    encode_string(j, key);
    krb5int_buf_add(&j->buf, ":");
    j->ret = encode_value(j, value);
    if (j->ret)
        return;
}

static int
encode_value(struct encode_ctx *j, k5_json_value val)
{
    k5_json_tid type;
    int first = 0, ret;
    size_t i, len;

    if (val == NULL)
        return EINVAL;

    type = k5_json_get_tid(val);
    switch (type) {
    case K5_JSON_TID_ARRAY:
        krb5int_buf_add(&j->buf, "[");
        len = k5_json_array_length(val);
        for (i = 0; i < len; i++) {
            if (i != 0)
                krb5int_buf_add(&j->buf, ",");
            ret = encode_value(j, k5_json_array_get(val, i));
            if (ret)
                return ret;
        }
        krb5int_buf_add(&j->buf, "]");
        break;

    case K5_JSON_TID_OBJECT:
        krb5int_buf_add(&j->buf, "{");
        first = j->first;
        j->first = 1;
        k5_json_object_iterate(val, encode_dict_entry, j);
        krb5int_buf_add(&j->buf, "}");
        j->first = first;
        break;

    case K5_JSON_TID_STRING:
        encode_string(j, k5_json_string_utf8(val));
        break;

    case K5_JSON_TID_NUMBER:
        krb5int_buf_add_fmt(&j->buf, "%lld", k5_json_number_value(val));
        break;

    case K5_JSON_TID_NULL:
        krb5int_buf_add(&j->buf, "null");
        break;

    case K5_JSON_TID_BOOL:
        krb5int_buf_add(&j->buf, k5_json_bool_value(val) ? "true" : "false");
        break;

    default:
        return 1;
    }
    return 0;
}

char *
k5_json_encode(k5_json_value val)
{
    struct encode_ctx j;

    j.ret = 0;
    j.first = 1;
    krb5int_buf_init_dynamic(&j.buf);
    if (encode_value(&j, val)) {
        krb5int_free_buf(&j.buf);
        return NULL;
    }
    return krb5int_buf_data(&j.buf);
}

/*** JSON decoding ***/

struct decode_ctx {
    const unsigned char *p;
    size_t depth;
};

static k5_json_value
parse_value(struct decode_ctx *ctx);

/* Consume whitespace.  Return 0 if there is anything left to parse after the
 * whitespace, -1 if not. */
static int
white_spaces(struct decode_ctx *ctx)
{
    unsigned char c;

    for (; *ctx->p != '\0'; ctx->p++) {
        c = *ctx->p;
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n')
            return 0;
    }
    return -1;
}

/* Return true if c is a decimal digit. */
static inline int
is_digit(unsigned char c)
{
    return ('0' <= c && c <= '9');
}

/* Return true if c is a hexadecimal digit (per RFC 5234 HEXDIG). */
static inline int
is_hex_digit(unsigned char c)
{
    return is_digit(c) || ('A' <= c && c <= 'F');
}

/* Return the numeric value of a hex digit; aborts if c is not a hex digit. */
static inline unsigned int
hexval(unsigned char c)
{
    if (is_digit(c))
        return c - '0';
    else if ('A' <= c && c <= 'F')
        return c - 'A' + 10;
    abort();
}

/* Parse a JSON number (which must be an integer in the signed 64-bit range; we
 * do not allow floating-point numbers). */
static k5_json_number
parse_number(struct decode_ctx *ctx)
{
    const unsigned long long umax = ~0ULL, smax = (1ULL << 63) - 1;
    unsigned long long number = 0;
    int neg = 1;

    if (*ctx->p == '-') {
        neg = -1;
        ctx->p++;
    }

    if (!is_digit(*ctx->p))
        return NULL;

    /* Read the number into an unsigned 64-bit container, ensuring that we
     * don't overflow it. */
    while (is_digit(*ctx->p)) {
        if (number + 1 > umax / 10)
            return NULL;
        number = (number * 10) + (*ctx->p - '0');
        ctx->p++;
    }

    /* Make sure the unsigned 64-bit value fits in the signed 64-bit range. */
    if (number > smax + 1 || (number > smax && neg == 1))
        return NULL;

    return k5_json_number_create(number * neg);
}

/* Parse a JSON string (which must not quote Unicode code points above 256). */
static char *
parse_string(struct decode_ctx *ctx)
{
    const unsigned char *p, *start, *end = NULL;
    const char *q;
    char *buf, *pos;
    unsigned int code;

    /* Find the start and end of the string. */
    if (*ctx->p != '"')
        return NULL;
    start = ++ctx->p;
    for (; *ctx->p != '\0'; ctx->p++) {
        if (*ctx->p == '\\') {
            ctx->p++;
            if (*ctx->p == '\0')
                return NULL;
        } else if (*ctx->p == '"') {
            end = ctx->p++;
            break;
        }
    }
    if (end == NULL)
        return NULL;

    pos = buf = malloc(end - start + 1);
    if (buf == NULL)
        return NULL;
    for (p = start; p < end;) {
        if (*p == '\\') {
            p++;
            if (*p == 'u' && is_hex_digit(p[1]) && is_hex_digit(p[2]) &&
                is_hex_digit(p[3]) && is_hex_digit(p[4])) {
                code = (hexval(p[1]) << 12) | (hexval(p[2]) << 8) |
                    (hexval(p[3]) << 4) | hexval(p[4]);
                if (code <= 0xff) {
                    *pos++ = code;
                } else {
                    /* Code points above 0xff don't need to be quoted, so we
                     * don't implement translating those into UTF-8. */
                    free(buf);
                    return NULL;
                }
                p += 5;
            } else {
                q = strchr(quotemap_json, *p);
                if (q != NULL) {
                    *pos++ = quotemap_c[q - quotemap_json];
                } else {
                    free(buf);
                    return NULL;
                }
                p++;
            }
        } else {
            *pos++ = *p++;
        }
    }
    *pos = '\0';
    return buf;
}

/*
 * Parse an object association and the following comma.  Return 1 if an
 * association was parsed, 0 if the end of the object was reached, and -1 on
 * error.
 */
static int
parse_pair(k5_json_object obj, struct decode_ctx *ctx)
{
    char *key = NULL;
    k5_json_value value;

    if (white_spaces(ctx))
        goto err;

    /* Check for the end of the object. */
    if (*ctx->p == '}') {
        ctx->p++;
        return 0;
    }

    /* Parse the key and value. */
    key = parse_string(ctx);
    if (key == NULL)
        goto err;
    if (white_spaces(ctx))
        goto err;
    if (*ctx->p != ':')
        goto err;
    ctx->p++;
    if (white_spaces(ctx))
        goto err;
    value = parse_value(ctx);
    if (value == NULL) {
        free(key);
        return -1;
    }

    /* Add the key and value to the object. */
    k5_json_object_set(obj, key, value);
    free(key);
    key = NULL;
    k5_json_release(value);

    /* Consume the following comma if this isn't the last item. */
    if (white_spaces(ctx))
        goto err;
    if (*ctx->p == ',')
        ctx->p++;
    else if (*ctx->p != '}')
        goto err;

    return 1;

err:
    free(key);
    return -1;
}

/* Parse a JSON object. */
static k5_json_object
parse_object(struct decode_ctx *ctx)
{
    k5_json_object obj;
    int ret;

    obj = k5_json_object_create();
    if (obj == NULL)
        return NULL;

    ctx->p++;
    while ((ret = parse_pair(obj, ctx)) > 0)
        ;
    if (ret < 0) {
        k5_json_release(obj);
        return NULL;
    }
    return obj;
}

/* Parse a JSON array item and the following comma.  Return 1 if an item was
 * parsed, 0 if the end of the array was reached, and -1 on error. */
static int
parse_item(k5_json_array array, struct decode_ctx *ctx)
{
    k5_json_value value;

    if (white_spaces(ctx))
        return -1;

    if (*ctx->p == ']') {
        ctx->p++;
        return 0;
    }

    value = parse_value(ctx);
    if (value == NULL)
        return -1;

    k5_json_array_add(array, value);
    k5_json_release(value);

    if (white_spaces(ctx))
        return -1;

    if (*ctx->p == ',')
        ctx->p++;
    else if (*ctx->p != ']')
        return -1;
    return 1;
}

/* Parse a JSON array. */
static k5_json_array
parse_array(struct decode_ctx *ctx)
{
    k5_json_array array = k5_json_array_create();
    int ret;

    assert(*ctx->p == '[');
    ctx->p += 1;

    while ((ret = parse_item(array, ctx)) > 0)
        ;
    if (ret < 0) {
        k5_json_release(array);
        return NULL;
    }
    return array;
}

/* Parse a JSON value of any type. */
static k5_json_value
parse_value(struct decode_ctx *ctx)
{
    k5_json_value v;
    char *str;

    if (white_spaces(ctx))
        return NULL;

    if (*ctx->p == '"') {
        str = parse_string(ctx);
        if (str == NULL)
            return NULL;
        v = k5_json_string_create(str);
        free(str);
        return v;
    } else if (*ctx->p == '{') {
        if (ctx->depth-- == 1)
            return NULL;
        v = parse_object(ctx);
        ctx->depth++;
        return v;
    } else if (*ctx->p == '[') {
        if (ctx->depth-- == 1)
            return NULL;
        v = parse_array(ctx);
        ctx->depth++;
        return v;
    } else if (is_digit(*ctx->p) || *ctx->p == '-') {
        return parse_number(ctx);
    }

    if (strncmp((char *)ctx->p, "null", 4) == 0) {
        ctx->p += 4;
        return k5_json_null_create();
    } else if (strncmp((char *)ctx->p, "true", 4) == 0) {
        ctx->p += 4;
        return k5_json_bool_create(1);
    } else if (strncmp((char *)ctx->p, "false", 5) == 0) {
        ctx->p += 5;
        return k5_json_bool_create(0);
    }

    return NULL;
}

k5_json_value
k5_json_decode(const char *string)
{
    struct decode_ctx ctx;
    k5_json_value v;

    ctx.p = (unsigned char *)string;
    ctx.depth = MAX_DECODE_DEPTH;
    v = parse_value(&ctx);
    if (white_spaces(&ctx) == 0) {
        k5_json_release(v);
        return NULL;
    }
    return v;
}
