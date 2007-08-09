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

#ifndef __KHIMAIRA_KCDB_CREDENTIAL_H
#define __KHIMAIRA_KCDB_CREDENTIAL_H

/* Credentials */

typedef struct kcdb_cred_t {
    khm_int32   magic;
    khm_ui_8    id; /* serial number */
    kcdb_identity * identity;
    khm_int32   type;
    wchar_t *   name;

    khm_int32   flags;
    khm_int32   refcount;

    kcdb_buf    buf;

    LDCL(struct kcdb_cred_t);
} kcdb_cred;

#define KCDB_CRED_MAGIC 0x38fb84a6

extern CRITICAL_SECTION cs_creds;
extern kcdb_cred * kcdb_creds;
extern RWLOCK l_creds;
extern khm_ui_8 kcdb_cred_id;

#define kcdb_cred_val_exist(c,a)    kcdb_buf_val_exist(&(c)->buf, a)
#define kcdb_cred_buf_exist(c,a)    kcdb_buf_exist(&(c)->buf, a)
#define kcdb_cred_buf_get(c,a)      kcdb_buf_get(&(c)->buf, a)
#define kcdb_cred_buf_size(c,a)     kcdb_buf_size(&(c)->buf, a)

#define kcdb_cred_is_cred(c)        ((c) && ((kcdb_cred *) c)->magic == KCDB_CRED_MAGIC)
#define kcdb_cred_is_active_cred(c) (kcdb_cred_is_cred(c) && !(((kcdb_cred *) c)->flags & KCDB_CRED_FLAG_DELETED))

#define kcdb_cred_lock_read()       (LockObtainRead(&l_creds))
#define kcdb_cred_unlock_read()     (LockReleaseRead(&l_creds))
#define kcdb_cred_lock_write()      (LockObtainWrite(&l_creds))
#define kcdb_cred_unlock_write()    (LockReleaseWrite(&l_creds))

void kcdb_cred_init(void);
void kcdb_cred_exit(void);
void kcdb_cred_check_and_delete(khm_handle vcred);

#endif
