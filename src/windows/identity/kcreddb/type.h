/*
 * Copyright (c) 2005 Massachusetts Institute of Technology
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/* $Id$ */

#ifndef __KHIMAIRA_KCDB_TYPE_H
#define __KHIMAIRA_KCDB_TYPE_H

/* Types */

typedef struct kcdb_type_i_t {
    kcdb_type type;

    khm_int32 refcount;

    struct kcdb_type_i_t * next;
    struct kcdb_type_i_t * prev;
} kcdb_type_i;

#define KCDB_TYPE_HASH_SIZE 31

#define KCDB_TYPE_FLAG_DELETED 8

void kcdb_type_init(void);
void kcdb_type_exit(void);
void kcdb_type_add_ref(const void *key, void *vt);
void kcdb_type_del_ref(const void *key, void *vt);
void kcdb_type_msg_completion(kmq_message * m);
khm_int32 kcdb_type_hold(kcdb_type_i * t);
khm_int32 kcdb_type_release(kcdb_type_i * t);
void kcdb_type_check_and_delete(khm_int32 id);
void kcdb_type_post_message(khm_int32 op, kcdb_type_i * t);

khm_int32 KHMAPI kcdb_type_void_toString(
    const void * d,
    khm_size cbd,
    wchar_t * buffer,
    khm_size * cb_buf,
    khm_int32 flags);

khm_boolean KHMAPI kcdb_type_void_isValid(
    const void * d,
    khm_size cbd);

khm_int32 KHMAPI kcdb_type_void_comp(
    const void * d1,
    khm_size cbd1,
    const void * d2,
    khm_size cbd2);

khm_int32 KHMAPI kcdb_type_void_dup(
    const void * d_src,
    khm_size cbd_src,
    void * d_dst,
    khm_size * cbd_dst);

khm_int32 KHMAPI kcdb_type_string_toString(
    const void * d,
    khm_size cbd,
    wchar_t * buffer,
    khm_size * cb_buf,
    khm_int32 flags);

khm_boolean KHMAPI kcdb_type_string_isValid(
    const void * d,
    khm_size cbd);

khm_int32 KHMAPI kcdb_type_string_comp(
    const void * d1,
    khm_size cbd1,
    const void * d2,
    khm_size cbd2);

khm_int32 KHMAPI kcdb_type_string_dup(
    const void * d_src,
    khm_size cbd_src,
    void * d_dst,
    khm_size * cbd_dst);

khm_int32 KHMAPI kcdb_type_date_toString(
    const void * d,
    khm_size cbd,
    wchar_t * buffer,
    khm_size * cb_buf,
    khm_int32 flags);

khm_boolean KHMAPI kcdb_type_date_isValid(
    const void * d,
    khm_size cbd);

khm_int32 KHMAPI kcdb_type_date_comp(
    const void * d1,
    khm_size cbd1,
    const void * d2,
    khm_size cbd2);

khm_int32 KHMAPI kcdb_type_date_dup(
    const void * d_src,
    khm_size cbd_src,
    void * d_dst,
    khm_size * cbd_dst);

khm_int32 KHMAPI kcdb_type_interval_toString(
    const void * d,
    khm_size cbd,
    wchar_t * buffer,
    khm_size * cb_buf,
    khm_int32 flags);

khm_boolean KHMAPI kcdb_type_interval_isValid(
    const void * d,
    khm_size cbd);

khm_int32 KHMAPI kcdb_type_interval_comp(
    const void * d1,
    khm_size cbd1,
    const void * d2,
    khm_size cbd2);

khm_int32 KHMAPI kcdb_type_interval_dup(
    const void * d_src,
    khm_size cbd_src,
    void * d_dst,
    khm_size * cbd_dst);

khm_int32 KHMAPI kcdb_type_int32_toString(
    const void * d,
    khm_size cbd,
    wchar_t * buffer,
    khm_size * cb_buf,
    khm_int32 flags);

khm_boolean KHMAPI kcdb_type_int32_isValid(
    const void * d,
    khm_size cbd);

khm_int32 KHMAPI kcdb_type_int32_comp(
    const void * d1,
    khm_size cbd1,
    const void * d2,
    khm_size cbd2);

khm_int32 KHMAPI kcdb_type_int32_dup(
    const void * d_src,
    khm_size cbd_src,
    void * d_dst,
    khm_size * cbd_dst);

khm_int32 KHMAPI kcdb_type_int64_toString(
    const void * d,
    khm_size cbd,
    wchar_t * buffer,
    khm_size * cb_buf,
    khm_int32 flags);

khm_boolean KHMAPI kcdb_type_int64_isValid(
    const void * d,
    khm_size cbd);

khm_int32 KHMAPI kcdb_type_int64_comp(
    const void * d1,
    khm_size cbd1,
    const void * d2,
    khm_size cbd2);

khm_int32 KHMAPI kcdb_type_int64_dup(
    const void * d_src,
    khm_size cbd_src,
    void * d_dst,
    khm_size * cbd_dst);

khm_int32 KHMAPI kcdb_type_data_toString(
    const void * d,
    khm_size cbd,
    wchar_t * buffer,
    khm_size * cb_buf,
    khm_int32 flags);

khm_boolean KHMAPI kcdb_type_data_isValid(
    const void * d,
    khm_size cbd);

khm_int32 KHMAPI kcdb_type_data_comp(
    const void * d1,
    khm_size cbd1,
    const void * d2,
    khm_size cbd2);

khm_int32 KHMAPI kcdb_type_data_dup(
    const void * d_src,
    khm_size cbd_src,
    void * d_dst,
    khm_size * cbd_dst);

#endif
