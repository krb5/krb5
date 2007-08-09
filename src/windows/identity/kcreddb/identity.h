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

#ifndef __KHIMAIRA_KCDB_IDENTITY_H
#define __KHIMAIRA_KCDB_IDENTITY_H

/* Identity */

#define KCDB_IDENT_HASHTABLE_SIZE 31

typedef struct kcdb_identity_t {
    khm_int32 magic;
    wchar_t * name;
    khm_int32 flags;
    khm_int32 refcount;
    kcdb_buf  buf;
    khm_ui_4  refresh_cycle;
    LDCL(struct kcdb_identity_t);
} kcdb_identity;

#define KCDB_IDENT_MAGIC 0x31938d4f

extern hashtable * kcdb_identities_namemap;
extern khm_int32 kcdb_n_identities;
extern kcdb_identity * kcdb_identities; /* all identities */
extern kcdb_identity * kcdb_def_identity; /* default identity */
extern khm_ui_4 kcdb_ident_refresh_cycle;

void kcdbint_ident_init(void);
void kcdbint_ident_exit(void);
void kcdbint_ident_msg_completion(kmq_message * m);
void kcdbint_ident_post_message(khm_int32 op, kcdb_identity * id);

#define kcdb_is_identity(id) ((id) && ((kcdb_identity *)(id))->magic == KCDB_IDENT_MAGIC)
#define kcdb_is_active_identity(id) (kcdb_is_identity(id) && (((kcdb_identity *)(id))->flags & KCDB_IDENT_FLAG_ACTIVE))

#endif
