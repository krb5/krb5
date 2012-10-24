/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* include/k5-json.h - JSON declarations */
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

#ifndef K5_JSON_H
#define K5_JSON_H

#include <stddef.h>

#define K5_JSON_TID_NUMBER 0
#define K5_JSON_TID_NULL 1
#define K5_JSON_TID_BOOL 2
#define K5_JSON_TID_MEMORY 128
#define K5_JSON_TID_ARRAY 129
#define K5_JSON_TID_OBJECT 130
#define K5_JSON_TID_STRING 131

/*
 * The k5_json_value C type can represent any kind of JSON value.  It has no
 * static type safety since it is represented using a void pointer, so be
 * careful with it.  Its type can be checked dynamically with k5_json_get_tid()
 * and the above constants.
 */
typedef void *k5_json_value;
typedef unsigned int k5_json_tid;

k5_json_tid k5_json_get_tid(k5_json_value val);

/*
 * k5_json_value objects are reference-counted.  These functions increment and
 * decrement the refcount, possibly freeing the value.  k5_json_retain returns
 * its argument and always succeeds.  Both functions gracefully accept NULL.
 */
void *k5_json_retain(k5_json_value val);
void k5_json_release(k5_json_value val);

/*
 * Unless otherwise specified, the following functions return NULL on error
 * (generally only if out of memory) if they return a pointer type, or 0 on
 * success and -1 on failure if they return int.
 */

/*
 * Null
 */

typedef struct k5_json_null_st *k5_json_null;

k5_json_null k5_json_null_create(void);

/*
 * Boolean
 */

typedef struct k5_json_bool_st *k5_json_bool;

k5_json_bool k5_json_bool_create(int truth);
int k5_json_bool_value(k5_json_bool bval);

/*
 * Array
 */

typedef struct k5_json_array_st *k5_json_array;

k5_json_array k5_json_array_create(void);
size_t k5_json_array_length(k5_json_array array);

/* Both of these functions increment the reference count on val. */
int k5_json_array_add(k5_json_array array, k5_json_value val);
void k5_json_array_set(k5_json_array array, size_t idx, k5_json_value val);

/* Get an alias to the idx-th element of array, without incrementing the
 * reference count.  The caller must check idx against the array length. */
k5_json_value k5_json_array_get(k5_json_array array, size_t idx);

/*
 * Object
 */

typedef struct k5_json_object_st *k5_json_object;
typedef void (*k5_json_object_iterator_fn)(void *arg, const char *key,
                                           k5_json_value val);

k5_json_object k5_json_object_create(void);
void k5_json_object_iterate(k5_json_object obj,
                            k5_json_object_iterator_fn func, void *arg);

/* Return the number of mappings in an object. */
size_t k5_json_object_count(k5_json_object obj);

/* Store val into object at key, incrementing val's reference count. */
int k5_json_object_set(k5_json_object obj, const char *key, k5_json_value val);

/* Get an alias to the object's value for key, without incrementing the
 * reference count.  Returns NULL if there is no value for key. */
k5_json_value k5_json_object_get(k5_json_object obj, const char *key);

/*
 * String
 */

typedef struct k5_json_string_st *k5_json_string;

k5_json_string k5_json_string_create(const char *string);
k5_json_string k5_json_string_create_len(const void *data, size_t len);
const char *k5_json_string_utf8(k5_json_string string);

/* Create a base64 string value from binary data. */
k5_json_string k5_json_string_create_base64(const void *data, size_t len);

/* Decode a base64 string.  Returns NULL and *len_out == 0 if out of memory,
 * NULL and *len == SIZE_MAX if string's contents aren't valid base64. */
void *k5_json_string_unbase64(k5_json_string string, size_t *len_out);

/*
 * Number
 */

typedef struct k5_json_number_st *k5_json_number;

k5_json_number k5_json_number_create(long long number);
long long k5_json_number_value(k5_json_number number);

/*
 * JSON encoding and decoding
 */

char *k5_json_encode(k5_json_value val);
k5_json_value k5_json_decode(const char *str);

#endif /* K5_JSON_H */
