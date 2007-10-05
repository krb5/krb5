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

#ifndef __KHIMAIRA_KCDB_ATTRIB_H
#define __KHIMAIRA_KCDB_ATTRIB_H

/* Attributes */

typedef struct kcdb_attrib_i_t {
    kcdb_attrib attr;

    khm_int32 refcount;

    struct kcdb_attrib_i_t * next;
    struct kcdb_attrib_i_t * prev;
} kcdb_attrib_i;

#define KCDB_ATTRIB_HASH_SIZE 31

void kcdb_attrib_init(void);
void kcdb_attrib_exit(void);
void kcdb_attrib_add_ref_func(const void * key, void * va);
void kcdb_attrib_del_ref_func(const void * key, void * va);
void kcdb_attrib_msg_completion(kmq_message * m);
khm_int32 kcdb_attrib_next_free_prop_id(khm_int32 * id);
khm_int32 kcdb_attrib_next_free_id(khm_int32 * id);
khm_int32 kcdb_attrib_hold(kcdb_attrib_i * ai);
khm_int32 kcdb_attrib_release(kcdb_attrib_i * ai);
void kcdb_attrib_post_message(khm_int32 op, kcdb_attrib_i * ai);
khm_int32 KHMAPI kcdb_attr_sys_cb(khm_handle cred, khm_int32 attr, void * buf, khm_size * pcb_buf);

#endif
