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

#ifndef __KHIMAIRA_KCDB_CREDTYPE_H
#define __KHIMAIRA_KCDB_CREDTYPE_H 

/* credtype */
typedef struct kcdb_credtype_i_t {
    kcdb_credtype ct;
    khm_int32 refcount;
    khm_int32 flags;

    struct kcdb_credtype_i_t * next;
    struct kcdb_credtype_i_t * prev;
} kcdb_credtype_i;

#define KCDB_CTI_FLAG_DELETED 8

extern CRITICAL_SECTION cs_credtype;
extern kcdb_credtype_i * kcdb_credtypes;
extern kcdb_credtype_i ** kcdb_credtype_tbl;

void kcdb_credtype_init(void);
void kcdb_credtype_exit(void);
void kcdb_credtype_check_and_delete(khm_int32 id);
khm_int32 kcdb_credtype_hold(kcdb_credtype_i * ict);
khm_int32 kcdb_credtype_release(kcdb_credtype_i * ict);
void kcdb_credtype_msg_completion(kmq_message * m);
void kcdb_credtype_post_message(khm_int32 op, kcdb_credtype * type);
khm_int32 kcdb_credtype_get_next_free_id(khm_int32 * id);

#endif
