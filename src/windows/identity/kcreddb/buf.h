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

#ifndef __KHIMAIRA_KCDB_BUF_H
#define __KHIMAIRA_KCDB_BUF_H

typedef struct tag_kcdb_buf_field {
    khm_ui_2    id;
    khm_ui_2    flags;
    khm_ui_4    offset;
    khm_ui_4    cbsize;
} kcdb_buf_field;

#define KCDB_CREDF_FLAG_EMPTY   0
#define KCDB_CREDF_FLAG_DATA    1
#define KCDB_CREDF_FLAG_INLINE  2
#define KCDB_CREDF_FLAG_ALLOCD  4

#define KCDB_BUFF_ID_INVALID    0xffff

typedef struct tag_kcdb_buf {
    void *      buffer;
    khm_size    cb_buffer;
    khm_size    cb_used;

    kcdb_buf_field * fields;
    khm_size    n_fields;
    khm_size    nc_fields;
} kcdb_buf;

#define KCDB_BUF_CBBUF_INITIAL  4096
#define KCDB_BUF_CBBUF_GROWTH   4096
#define KCDB_BUF_FIELDS_INITIAL 16
#define KCDB_BUF_FIELDS_GROWTH  16

#define KCDB_BUF_APPEND 0x8000

#define KCDB_BUF_INVALID_SLOT   0xf0000000
#define KCDB_BUF_DEFAULT        0xe0000000

#define KCDB_BUF_MAX_SLOTS      0x00004000

void    kcdb_buf_new(kcdb_buf * buf, khm_size n_slots);
void    kcdb_buf_delete(kcdb_buf * buf);
void    kcdb_buf_alloc(kcdb_buf * buf, khm_size slot, khm_ui_2 id, khm_size cbsize);
void    kcdb_buf_dup(kcdb_buf * dest, const kcdb_buf * src);
void    kcdb_buf_set_value(kcdb_buf * buf, khm_size slot, khm_ui_2 id, void * src, khm_size cb_src);
int     kcdb_buf_exist(kcdb_buf * buf, khm_size slot);
int     kcdb_buf_val_exist(kcdb_buf * buf, khm_size slot);
void *  kcdb_buf_get(kcdb_buf * buf, khm_size slot);
khm_size kcdb_buf_size(kcdb_buf * buf, khm_size slot);
void    kcdb_buf_set_value_flag(kcdb_buf * buf, khm_size slot);
khm_size kcdb_buf_slot_by_id(kcdb_buf * buf, khm_ui_2 id);

#endif
