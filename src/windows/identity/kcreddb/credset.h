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

#ifndef __KHIMAIRA_KCDB_CREDSET_H
#define __KHIMAIRA_KCDB_CREDSET_H

/* credset */

typedef struct kcdb_credset_credref_t {
    khm_int32 version;
    kcdb_cred * cred;
} kcdb_credset_credref;

typedef struct kcdb_credset_t {
    khm_int32 magic;
    khm_int32 flags;
    CRITICAL_SECTION cs;

    kcdb_credset_credref * clist;
    khm_int32 nc_clist; /* total capacity */
    khm_int32 nclist;   /* current load */

    khm_int32 version;  /* data version */

    khm_int32 seal_count;       /* number of seals applied to the
                                   credset */

    struct kcdb_credset_t * next;
    struct kcdb_credset_t * prev;
} kcdb_credset;

#define KCDB_CREDSET_MAGIC 0x63a84f8b

#define KCDB_CREDSET_FLAG_ROOT 1

/* the credset is in the process of being enumerated */
#define KCDB_CREDSET_FLAG_ENUM 2

#define kcdb_credset_is_credset(c) ((c) && ((kcdb_credset *)c)->magic == KCDB_CREDSET_MAGIC)

#define kcdb_credset_is_sealed(c) ((c)->seal_count != 0)

#define KCDB_CREDSET_INITIAL_SIZE 256
#define KCDB_CREDSET_GROWTH_FACTOR 256

void kcdb_credset_init(void);
void kcdb_credset_exit(void);
khm_int32 kcdb_credset_update_cred_ref(
    khm_handle credset,
    khm_handle cred);

#endif
