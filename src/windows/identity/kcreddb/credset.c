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

#include<kcreddbinternal.h>
#include<assert.h>

CRITICAL_SECTION cs_credset;
kcdb_credset * kcdb_credsets = NULL;
kcdb_credset * kcdb_root_credset = NULL;

void
kcdb_credset_init(void)
{
    khm_handle rc;

    InitializeCriticalSection(&cs_credset);
    kcdb_credsets = NULL;

    kcdb_credset_create(&rc);
    kcdb_root_credset = (kcdb_credset *) rc;
    kcdb_root_credset->flags |= KCDB_CREDSET_FLAG_ROOT;
}

void
kcdb_credset_exit(void)
{
    /*TODO: free the credsets */
    DeleteCriticalSection(&cs_credset);
}

/* called on an unreleased credset, or with credset::cs held */
void
kcdb_credset_buf_new(kcdb_credset * cs)
{
    cs->clist = PMALLOC(KCDB_CREDSET_INITIAL_SIZE *
                        sizeof(kcdb_credset_credref));
    ZeroMemory(cs->clist,
               KCDB_CREDSET_INITIAL_SIZE *
               sizeof(kcdb_credset_credref));
    cs->nc_clist = KCDB_CREDSET_INITIAL_SIZE;
    cs->nclist = 0;
}

/* called on an unreleased credset, or with credset::cs held */
void
kcdb_credset_buf_delete(kcdb_credset * cs)
{
    PFREE(cs->clist);
    cs->nc_clist = 0;
    cs->nclist = 0;
}

void
kcdb_credset_buf_assert_size(kcdb_credset * cs, khm_int32 nclist)
{
    if(cs->nc_clist < nclist) {
        kcdb_credset_credref * new_clist;

        /* nclist had better be greater than KCDB_CREDSET_INITIAL_SIZE */
        nclist = KCDB_CREDSET_INITIAL_SIZE +
            (((nclist - (KCDB_CREDSET_INITIAL_SIZE + 1)) / KCDB_CREDSET_GROWTH_FACTOR) + 1) *
            KCDB_CREDSET_GROWTH_FACTOR;

        new_clist = PCALLOC(nclist, sizeof(kcdb_credset_credref));

        memcpy(new_clist, cs->clist, cs->nclist * sizeof(kcdb_credset_credref));

        PFREE(cs->clist);

        cs->clist = new_clist;
    }
}

KHMEXP khm_int32 KHMAPI
kcdb_credset_create(khm_handle * result)
{
    kcdb_credset * cs;

    cs = PMALLOC(sizeof(kcdb_credset));
    ZeroMemory(cs, sizeof(kcdb_credset));

    cs->magic = KCDB_CREDSET_MAGIC;
    InitializeCriticalSection(&(cs->cs));
    LINIT(cs);
    kcdb_credset_buf_new(cs);
    cs->version = 0;
    cs->seal_count = 0;

    EnterCriticalSection(&cs_credset);
    LPUSH(&kcdb_credsets, cs);
    LeaveCriticalSection(&cs_credset);

    *result = (khm_handle) cs;

    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32 KHMAPI
kcdb_credset_delete(khm_handle vcredset)
{
    kcdb_credset * cs;
    int i;

    if(!kcdb_credset_is_credset(vcredset)) {
        return KHM_ERROR_INVALID_PARAM;
    }

    cs = (kcdb_credset *) vcredset;

    EnterCriticalSection(&cs_credset);
    LDELETE(&kcdb_credsets, cs);
    LeaveCriticalSection(&cs_credset);

    EnterCriticalSection(&(cs->cs));
    cs->magic = 0;

    for(i=0;i<cs->nclist;i++) {
        if(cs->clist[i].cred) {
            kcdb_cred_release((khm_handle) cs->clist[i].cred);
        }
    }
    kcdb_credset_buf_delete(cs);

    LeaveCriticalSection(&(cs->cs));
    DeleteCriticalSection(&(cs->cs));

    PFREE(cs);

    return KHM_ERROR_SUCCESS;
}

/*! \internal

Collect credentials from cs2 to cs1 which have already been selected into
cl1 and cl2.

- Credentials in cl2 that are not in cl1 will get added to cs1
- Credentials in cl1 that are not in cl2 will get removed from cs1
- Credentials in cl1 and cl2 will be updated in cs1

cl1 and cl2 will be modified.
*/
khm_int32
kcdb_credset_collect_core(kcdb_credset * cs1,
                          kcdb_cred ** cl1,
                          khm_int32 ncl1,
                          kcdb_credset * cs2,
                          kcdb_cred ** cl2,
                          khm_int32 ncl2,
                          khm_int32 * delta)
{
    int i, j;
    int ldelta = 0;
    khm_int32 rv;

    /* find matching creds and update them */
    for(i=0; i<ncl1; i++)
        if(cl1[i]) {
            for(j=0; j<ncl2; j++)
                if(cl2[j] && kcdb_creds_is_equal((khm_handle) cl1[i], (khm_handle) cl2[j])) {
                    /* they are equivalent. make them equal */

                    /* depending on whether any changes were made,
                        update ldelta with the proper bit flag */

                    rv = kcdb_cred_update(cl1[i], cl2[j]);
                    if (rv == KHM_ERROR_SUCCESS) {
                        kcdb_credset_update_cred_ref((khm_handle) cs1, (khm_handle) cl1[i]);
                        ldelta |= KCDB_DELTA_MODIFY;
                    }

                    cl2[j] = NULL;
                    cl1[i] = NULL;
                    break;
                }
        }

    /* all the creds that are left in cl1 need to be removed */
    for(i=0; i<ncl1; i++)
        if(cl1[i]) {
            kcdb_credset_del_cred_ref((khm_handle) cs1, (khm_handle) cl1[i]);
            cl1[i] = NULL;
            ldelta |= KCDB_DELTA_DEL;
        }

    /* all the creds in cl2 need to be added to cs1 */
    for(j=0; j<ncl2; j++)
        if(cl2[j]) {
            /* duplicate the credential and add it if we are adding it to the
               root credential store. */
            if(cs1 == kcdb_root_credset) {
                khm_handle h;

                if(KHM_SUCCEEDED(kcdb_cred_dup((khm_handle) cl2[j], &h))) {
                    kcdb_credset_add_cred((khm_handle) cs1, h, -1);
                    kcdb_cred_release(h);
                }
            } else
                kcdb_credset_add_cred((khm_handle) cs1, cl2[j], -1);
            cl2[j] = NULL;
            ldelta |= KCDB_DELTA_ADD;
        }

    if(delta)
        *delta = ldelta;

    if((cs1 == kcdb_root_credset) && ldelta) {
        /* something changed in the root credential set */
        kmq_post_message(KMSG_CRED,KMSG_CRED_ROOTDELTA,ldelta,NULL);
    }
    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32 KHMAPI
kcdb_credset_collect(khm_handle cs_dest,
		     khm_handle cs_src,
		     khm_handle identity,
		     khm_int32 type,
		     khm_int32 * delta)
{
    kcdb_credset * cs;
    kcdb_credset * rcs;
    khm_int32 code = KHM_ERROR_SUCCESS;
    kcdb_cred ** r_sel = NULL;
    kcdb_cred ** c_sel = NULL;
    int nr_sel, nc_sel;
    int i;

    if((cs_src && !kcdb_credset_is_credset(cs_src)) ||
        (cs_dest && !kcdb_credset_is_credset(cs_dest)) ||
        (cs_src == cs_dest)) /* works because credsets use shared
                                handles */
        return KHM_ERROR_INVALID_PARAM;

    if(identity && !kcdb_is_active_identity(identity))
        return KHM_ERROR_INVALID_PARAM;

    if(cs_src)
        cs = (kcdb_credset *) cs_src;
    else
        cs = kcdb_root_credset;

    if(cs_dest)
        rcs = (kcdb_credset *) cs_dest;
    else
        rcs = kcdb_root_credset;

    if (kcdb_credset_is_sealed(rcs))
        return KHM_ERROR_INVALID_OPERATION;

    EnterCriticalSection(&(cs->cs));
    EnterCriticalSection(&(rcs->cs));

    /* enumerate through the root and given credential sets and select
       the ones we want */

    if(rcs->nclist > 0)
        r_sel = PMALLOC(sizeof(kcdb_cred *) * rcs->nclist);
    if(cs->nclist > 0)
        c_sel = PMALLOC(sizeof(kcdb_cred *) * cs->nclist);
    nr_sel = 0;
    nc_sel = 0;

    for(i=0; i<rcs->nclist; i++) {
        if(rcs->clist[i].cred &&
            (!identity || rcs->clist[i].cred->identity == identity) &&
            (type==KCDB_CREDTYPE_ALL || rcs->clist[i].cred->type == type))
        {
            r_sel[nr_sel++] = rcs->clist[i].cred;
        }
    }

    for(i=0; i<cs->nclist; i++) {
        if(cs->clist[i].cred &&
            (!identity || cs->clist[i].cred->identity == identity) &&
            (type==KCDB_CREDTYPE_ALL || cs->clist[i].cred->type == type))
        {
            c_sel[nc_sel++] = cs->clist[i].cred;
        }
    }

    rcs->version++;

    code = kcdb_credset_collect_core(
        rcs,
        r_sel,
        nr_sel,
        cs,
        c_sel,
        nc_sel,
        delta);

    LeaveCriticalSection(&(rcs->cs));
    LeaveCriticalSection(&(cs->cs));

    if(r_sel)
        PFREE(r_sel);
    if(c_sel)
        PFREE(c_sel);

    if (cs_dest == NULL) {
        kcdb_identity_refresh_all();
    }

    return code;
}

KHMEXP khm_int32 KHMAPI
kcdb_credset_collect_filtered(khm_handle cs_dest,
			      khm_handle cs_src,
			      kcdb_cred_filter_func filter,
			      void * rock,
			      khm_int32 * delta)
{
    kcdb_credset * cs;
    kcdb_credset * rcs;
    khm_int32 code = KHM_ERROR_SUCCESS;
    kcdb_cred ** r_sel = NULL;
    kcdb_cred ** c_sel = NULL;
    int nr_sel, nc_sel;
    int i;
    khm_int32 cs_f = 0;
    khm_int32 rcs_f = 0;

    if((cs_src && !kcdb_credset_is_credset(cs_src)) ||
        (cs_dest && !kcdb_credset_is_credset(cs_dest)) ||
        (cs_src == cs_dest)) /* works because credsets use shared
                                handles */
        return KHM_ERROR_INVALID_PARAM;

    if(cs_src)
        cs = (kcdb_credset *) cs_src;
    else {
        cs = kcdb_root_credset;
        cs_f = KCDB_CREDCOLL_FILTER_ROOT;
    }

    if(cs_dest)
        rcs = (kcdb_credset *) cs_dest;
    else {
        rcs = kcdb_root_credset;
        rcs_f = KCDB_CREDCOLL_FILTER_ROOT;
    }

    if (kcdb_credset_is_sealed(rcs))
        return KHM_ERROR_INVALID_OPERATION;

    EnterCriticalSection(&(cs->cs));
    EnterCriticalSection(&(rcs->cs));

#ifdef DEBUG
    assert(!(rcs->flags & KCDB_CREDSET_FLAG_ENUM));
    assert(!(cs->flags & KCDB_CREDSET_FLAG_ENUM));
#endif

    if(rcs->nclist)
        r_sel = PMALLOC(sizeof(kcdb_cred *) * rcs->nclist);
    if(cs->nclist)
        c_sel = PMALLOC(sizeof(kcdb_cred *) * cs->nclist);
    nr_sel = 0;
    nc_sel = 0;

    rcs->flags |= KCDB_CREDSET_FLAG_ENUM;

    for(i=0; i<rcs->nclist; i++) {
        if(rcs->clist[i].cred &&
           (*filter)((khm_handle)rcs->clist[i].cred,
                     KCDB_CREDCOLL_FILTER_DEST | rcs_f,
                     rock))
        {
            r_sel[nr_sel++] = rcs->clist[i].cred;
        }
    }

    rcs->flags &= ~KCDB_CREDSET_FLAG_ENUM;
    cs->flags |= KCDB_CREDSET_FLAG_ENUM;

    for(i=0; i<cs->nclist; i++) {
        if(cs->clist[i].cred && filter((khm_handle)rcs->clist[i].cred, KCDB_CREDCOLL_FILTER_SRC | cs_f, rock))
        {
            c_sel[nc_sel++] = cs->clist[i].cred;
        }
    }

    cs->flags &= ~KCDB_CREDSET_FLAG_ENUM;

    rcs->version++;

    code = kcdb_credset_collect_core(
        rcs,
        r_sel,
        nr_sel,
        cs,
        c_sel,
        nc_sel,
        delta);

    LeaveCriticalSection(&(rcs->cs));
    LeaveCriticalSection(&(cs->cs));

    if(r_sel)
        PFREE(r_sel);
    if(c_sel)
        PFREE(c_sel);

    if (cs_dest == NULL) {
        kcdb_identity_refresh_all();
    }

    return code;
}

KHMEXP khm_int32 KHMAPI
kcdb_credset_flush(khm_handle vcredset)
{
    int i;
    kcdb_credset * cs;

    if(!kcdb_credset_is_credset(vcredset))
        return KHM_ERROR_INVALID_PARAM;

    cs = (kcdb_credset *) vcredset;

    if (kcdb_credset_is_sealed(cs))
        return KHM_ERROR_INVALID_OPERATION;

    EnterCriticalSection(&(cs->cs));

#ifdef DEBUG
    assert(!(cs->flags & KCDB_CREDSET_FLAG_ENUM));
#endif

    for(i=0;i<cs->nclist;i++) {
        if(cs->clist[i].cred) {
            kcdb_cred_release((khm_handle) cs->clist[i].cred);
        }
    }
    cs->nclist = 0;
    LeaveCriticalSection(&(cs->cs));

    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32 KHMAPI
kcdb_credset_extract(khm_handle destcredset,
		     khm_handle sourcecredset,
		     khm_handle identity,
		     khm_int32 type)
{
    khm_int32 code = KHM_ERROR_SUCCESS;
    kcdb_credset * dest;
    kcdb_credset * src;
    int isRoot = 0;
    khm_size srcSize = 0;
    int i;

    if(!kcdb_credset_is_credset(destcredset))
        return KHM_ERROR_INVALID_PARAM;

    if(sourcecredset) {
        if(!kcdb_credset_is_credset(sourcecredset))
            return KHM_ERROR_INVALID_PARAM;
    } else {
        sourcecredset = kcdb_root_credset;
    }

    if (sourcecredset == kcdb_root_credset)
        isRoot = 1;

    src = (kcdb_credset *) sourcecredset;
    dest = (kcdb_credset *) destcredset;

    if (kcdb_credset_is_sealed(dest))
        return KHM_ERROR_INVALID_OPERATION;

    EnterCriticalSection(&(src->cs));
    EnterCriticalSection(&(dest->cs));

#ifdef DEBUG
    assert(!(dest->flags & KCDB_CREDSET_FLAG_ENUM));
#endif

    if(KHM_FAILED(kcdb_credset_get_size(sourcecredset, &srcSize))) {
        code = KHM_ERROR_UNKNOWN;
        goto _exit;
    }

    kcdb_cred_lock_read();

    for(i=0; i < (int) srcSize; i++) {
        kcdb_cred * c;

        c = src->clist[i].cred;
        if(kcdb_cred_is_active_cred((khm_handle) c) &&
            (!identity || c->identity == identity) &&
            (type < 0 || c->type == type))
        {
            if(isRoot) {
                khm_handle newcred;

                kcdb_cred_unlock_read();
                kcdb_cred_dup((khm_handle) c, &newcred);
                kcdb_credset_add_cred(destcredset, newcred, -1);
                kcdb_cred_release(newcred);
                kcdb_cred_lock_read();
            } else {
                kcdb_cred_unlock_read();
                kcdb_credset_add_cred(destcredset, (khm_handle) c, -1);
                kcdb_cred_lock_read();
            }
        }
    }

    kcdb_cred_unlock_read();

_exit:
    LeaveCriticalSection(&(dest->cs));
    LeaveCriticalSection(&(src->cs));

    return code;
}

KHMEXP khm_int32 KHMAPI
kcdb_credset_extract_filtered(khm_handle destcredset,
			      khm_handle sourcecredset,
			      kcdb_cred_filter_func filter,
			      void * rock)
{
    khm_int32 code = KHM_ERROR_SUCCESS;
    kcdb_credset * dest;
    kcdb_credset * src;
    int isRoot = 0;
    khm_size srcSize = 0;
    int i;

    if(!kcdb_credset_is_credset(destcredset))
        return KHM_ERROR_INVALID_PARAM;

    if(sourcecredset) {
        if(!kcdb_credset_is_credset(sourcecredset))
            return KHM_ERROR_INVALID_PARAM;
    } else {
        sourcecredset = kcdb_root_credset;
        isRoot = 1;
    }

    src = (kcdb_credset *) sourcecredset;
    dest = (kcdb_credset *) destcredset;

    if (kcdb_credset_is_sealed(dest))
        return KHM_ERROR_INVALID_OPERATION;

    EnterCriticalSection(&(src->cs));
    EnterCriticalSection(&(dest->cs));

#ifdef DEBUG
    assert(!(dest->flags & KCDB_CREDSET_FLAG_ENUM));
#endif

    if(KHM_FAILED(kcdb_credset_get_size(sourcecredset, &srcSize))) {
        code = KHM_ERROR_UNKNOWN;
        goto _exit;
    }

    kcdb_cred_lock_read();

    dest->flags |= KCDB_CREDSET_FLAG_ENUM;

    for(i=0; i < (int) srcSize; i++) {
        kcdb_cred * c;

        c = src->clist[i].cred;
        if(kcdb_cred_is_active_cred((khm_handle) c) &&
            filter(c, 0, rock))
        {
            if(isRoot) {
                khm_handle newcred;

                kcdb_cred_unlock_read();
                kcdb_cred_dup((khm_handle) c, &newcred);
                kcdb_credset_add_cred(destcredset, newcred, -1);
                kcdb_cred_release(newcred);
                kcdb_cred_lock_read();
            } else {
                kcdb_cred_unlock_read();
                kcdb_credset_add_cred(destcredset, (khm_handle) c, -1);
                kcdb_cred_lock_read();
            }
        }
    }

    dest->flags &= ~KCDB_CREDSET_FLAG_ENUM;

    kcdb_cred_unlock_read();

_exit:
    LeaveCriticalSection(&(dest->cs));
    LeaveCriticalSection(&(src->cs));

    return code;
}

KHMEXP khm_int32 KHMAPI
kcdb_credset_apply(khm_handle vcredset, kcdb_cred_apply_func f,
		   void * rock)
{
    kcdb_credset * cs;
    khm_int32 rv = KHM_ERROR_SUCCESS;
    int i;

    if(vcredset != NULL && !kcdb_credset_is_credset(vcredset))
        return KHM_ERROR_INVALID_PARAM;

    if(vcredset == NULL) {
        cs = kcdb_root_credset;
    } else {
        cs = (kcdb_credset *) vcredset;
    }

    EnterCriticalSection(&cs->cs);

#ifdef DEBUG
    assert(!(cs->flags & KCDB_CREDSET_FLAG_ENUM));
#endif

    cs->flags |= KCDB_CREDSET_FLAG_ENUM;

    for(i=0; i<cs->nclist; i++) {
        if(!kcdb_cred_is_active_cred(cs->clist[i].cred))
            continue;

        if(KHM_FAILED(f((khm_handle) cs->clist[i].cred, rock)))
            break;
    }

    cs->flags &= ~KCDB_CREDSET_FLAG_ENUM;

    LeaveCriticalSection(&cs->cs);

    if(i<cs->nclist)
        rv = KHM_ERROR_EXIT;

    return rv;
}

KHMEXP khm_int32 KHMAPI
kcdb_credset_get_cred(khm_handle vcredset,
		      khm_int32 idx,
		      khm_handle * cred)
{
    kcdb_credset * cs;
    khm_int32 code = KHM_ERROR_SUCCESS;

    if(!kcdb_credset_is_credset(vcredset))
        return KHM_ERROR_INVALID_PARAM;

    cs = (kcdb_credset *) vcredset;

    *cred = NULL;

    EnterCriticalSection(&(cs->cs));
    if(idx < 0 || idx >= cs->nclist)
        code = KHM_ERROR_OUT_OF_BOUNDS;
    else if(!cs->clist[idx].cred || !kcdb_cred_is_active_cred((khm_handle) cs->clist[idx].cred)) {
        code = KHM_ERROR_DELETED;
        if(cs->clist[idx].cred) {
            kcdb_cred_release((khm_handle) cs->clist[idx].cred);
            cs->clist[idx].cred = NULL;
        }
    }
    else {
        kcdb_cred_hold((khm_handle) cs->clist[idx].cred);
        *cred = cs->clist[idx].cred;
    }
    LeaveCriticalSection(&(cs->cs));
    return code;
}

KHMEXP khm_int32 KHMAPI
kcdb_credset_find_filtered(khm_handle credset,
			   khm_int32 idx_start,
			   kcdb_cred_filter_func f,
			   void * rock,
			   khm_handle * cred,
			   khm_int32 * idx)
{
    kcdb_credset * cs;
    khm_int32 rv = KHM_ERROR_SUCCESS;
    int i;

    if((credset && !kcdb_credset_is_credset(credset)) || !f)
        return KHM_ERROR_INVALID_PARAM;

    if(credset)
        cs = (kcdb_credset *) credset;
    else
        cs = kcdb_root_credset;

    EnterCriticalSection(&cs->cs);

    if(idx_start < 0)
        i = 0;
    else
        i = idx_start + 1;

#ifdef DEBUG
    assert(!(cs->flags & KCDB_CREDSET_FLAG_ENUM));
#endif

    cs->flags |= KCDB_CREDSET_FLAG_ENUM;

    for(; i < cs->nclist; i++) {
        if(kcdb_cred_is_active_cred(cs->clist[i].cred) &&
            (*f)((khm_handle) cs->clist[i].cred, 0, rock) != 0)
            break;
    }

    cs->flags &= ~KCDB_CREDSET_FLAG_ENUM;

    if(i < cs->nclist) {
        if (cred) {
            *cred = (khm_handle) cs->clist[i].cred;
            kcdb_cred_hold(*cred);
        }

        if(idx) {
            *idx = i;
        }
    } else {
        rv = KHM_ERROR_NOT_FOUND;
    }

    LeaveCriticalSection(&cs->cs);

    return rv;
}

KHMEXP khm_int32 KHMAPI
kcdb_credset_find_cred(khm_handle vcredset,
                       khm_handle vcred_src,
                       khm_handle *cred_dest) {
    kcdb_credset * cs;
    khm_handle cred = NULL;
    int idx;

    if (!kcdb_credset_is_credset(vcredset))
        return KHM_ERROR_INVALID_PARAM;

    if (!kcdb_cred_is_active_cred(vcred_src))
        return KHM_ERROR_INVALID_PARAM;

    cs = (kcdb_credset *) vcredset;

    EnterCriticalSection(&cs->cs);
    for (idx = 0; idx < cs->nclist; idx++) {
        if (cs->clist[idx].cred &&
            kcdb_creds_is_equal(vcred_src, cs->clist[idx].cred)) {
            cred = cs->clist[idx].cred;
            break;
        }
    }

    if (cred)
        kcdb_cred_hold(cred);

    LeaveCriticalSection(&cs->cs);

    if (cred) {
        if (cred_dest)
            *cred_dest = cred;
        else
            kcdb_cred_release(cred);

        return KHM_ERROR_SUCCESS;
    } else {
        return KHM_ERROR_NOT_FOUND;
    }
}

KHMEXP khm_int32 KHMAPI
kcdb_credset_del_cred(khm_handle vcredset,
		      khm_int32 idx)
{
    kcdb_credset * cs;
    khm_int32 code = KHM_ERROR_SUCCESS;

    if(!kcdb_credset_is_credset(vcredset))
        return KHM_ERROR_INVALID_PARAM;

    cs = (kcdb_credset *) vcredset;

    if (kcdb_credset_is_sealed(cs))
        return KHM_ERROR_INVALID_OPERATION;

    EnterCriticalSection(&(cs->cs));
    if(idx < 0 || idx >= cs->nclist) {
        code = KHM_ERROR_INVALID_PARAM;
        goto _exit;
    }

    if(cs->clist[idx].cred)
        kcdb_cred_release((khm_handle) cs->clist[idx].cred);

    if (!(cs->flags & KCDB_CREDSET_FLAG_ENUM)) {

        if(idx + 1 < cs->nclist)
            memmove(&(cs->clist[idx]),
                    &(cs->clist[idx+1]),
                    sizeof(kcdb_credset_credref) *
                    (cs->nclist - (idx + 1)));

        cs->nclist--;
    } else {
        cs->clist[idx].cred = NULL;
    }

_exit:
    LeaveCriticalSection(&(cs->cs));

    return code;
}

khm_int32
kcdb_credset_update_cred_ref(khm_handle credset,
			     khm_handle cred)
{
    kcdb_credset * cs;
    khm_int32 code = KHM_ERROR_SUCCESS;
    int i;

    if(!kcdb_credset_is_credset(credset))
        return KHM_ERROR_INVALID_PARAM;

    cs = (kcdb_credset *) credset;

    EnterCriticalSection(&(cs->cs));

    for(i=0; i<cs->nclist; i++) {
        if(cs->clist[i].cred == cred)
            break;
    }

    if(i<cs->nclist) {
        cs->clist[i].version = cs->version;
    } else {
        code = KHM_ERROR_NOT_FOUND;
    }

    LeaveCriticalSection(&(cs->cs));
    return code;
}

KHMEXP khm_int32 KHMAPI
kcdb_credset_del_cred_ref(khm_handle credset,
			  khm_handle cred)
{
    kcdb_credset * cs;
    khm_int32 code = KHM_ERROR_SUCCESS;
    int i;

    if(!kcdb_credset_is_credset(credset))
        return KHM_ERROR_INVALID_PARAM;

    cs = (kcdb_credset *) credset;

    if (kcdb_credset_is_sealed(cs))
        return KHM_ERROR_INVALID_OPERATION;

    EnterCriticalSection(&(cs->cs));

    for(i=0; i<cs->nclist; i++) {
        if(cs->clist[i].cred == cred)
            break;
    }

    if(i<cs->nclist) {
        code = kcdb_credset_del_cred(credset, i);
    } else {
        code = KHM_ERROR_NOT_FOUND;
    }

    LeaveCriticalSection(&(cs->cs));
    return code;
}

KHMEXP khm_int32 KHMAPI
kcdb_credset_add_cred(khm_handle credset,
		      khm_handle cred,
		      khm_int32 idx)
{
    int new_idx;
    kcdb_credset * cs;
    khm_int32 code = KHM_ERROR_SUCCESS;

    if(!kcdb_credset_is_credset(credset))
        return KHM_ERROR_INVALID_PARAM;

    cs = (kcdb_credset *) credset;

    if (kcdb_credset_is_sealed(cs))
        return KHM_ERROR_INVALID_OPERATION;

    EnterCriticalSection(&(cs->cs));

    kcdb_credset_buf_assert_size(cs, cs->nclist + 1);

    if(idx < 0 || idx > cs->nclist)
        new_idx = cs->nclist;
    else if(idx < cs->nclist){
#ifdef DEBUG
        assert(!(cs->flags & KCDB_CREDSET_FLAG_ENUM));
#endif
        memmove(&(cs->clist[idx+1]), &(cs->clist[idx]), (cs->nclist - idx)*sizeof(cs->clist[0]));
        new_idx = idx;
    } else
        new_idx = idx;

    kcdb_cred_hold(cred);

    cs->clist[new_idx].cred = (kcdb_cred *) cred;
    cs->clist[new_idx].version = cs->version;
    cs->nclist++;

    LeaveCriticalSection(&(cs->cs));
    return code;
}

KHMEXP khm_int32 KHMAPI
kcdb_credset_get_size(khm_handle credset,
		      khm_size * size)
{
    kcdb_credset * cs;

    *size = 0;

    /* we don't rely on this working, since we can't purge a sealed
       credset, although we can measure its size. */
    kcdb_credset_purge(credset);

    if (credset == NULL)
        cs = kcdb_root_credset;
    else
        cs = (kcdb_credset *) credset;

    EnterCriticalSection(&(cs->cs));
    /* while it may seem a bit redundant to get a lock, it ensures that
       that the size that we return is consistent with the current state
       of the credential set */
    *size = cs->nclist;
    LeaveCriticalSection(&(cs->cs));

    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32 KHMAPI
kcdb_credset_purge(khm_handle credset)
{
    khm_int32 code = KHM_ERROR_SUCCESS;
    kcdb_credset * cs;
    int i,j;

    if(!kcdb_credset_is_credset(credset))
        return KHM_ERROR_INVALID_PARAM;

    cs = (kcdb_credset *) credset;

    if (kcdb_credset_is_sealed(cs))
        return KHM_ERROR_INVALID_OPERATION;

    EnterCriticalSection(&(cs->cs));

    /* we can't purge a credset while an enumeration operation is in
       progress. */
    if (cs->flags & KCDB_CREDSET_FLAG_ENUM) {
        code = KHM_ERROR_INVALID_OPERATION;
        goto _exit;
    }

    for(i=0,j=0; i < cs->nclist; i++) {
        if(cs->clist[i].cred) {
            if(!kcdb_cred_is_active_cred((khm_handle) cs->clist[i].cred)) {
                kcdb_cred_release((khm_handle) cs->clist[i].cred);
            } else if(i != j) {
                cs->clist[j++] = cs->clist[i];
            } else
                j++;
        }
    }
    cs->nclist = j;

 _exit:
    LeaveCriticalSection(&(cs->cs));
    return code;
}

KHMEXP khm_int32 KHMAPI
kcdb_credset_seal(khm_handle credset) {
    kcdb_credset * cs;

    if (!kcdb_credset_is_credset(credset))
        return KHM_ERROR_INVALID_PARAM;

    cs = (kcdb_credset *) credset;

    EnterCriticalSection(&cs->cs);
    cs->seal_count++;
    LeaveCriticalSection(&cs->cs);

    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32 KHMAPI
kcdb_credset_unseal(khm_handle credset) {
    kcdb_credset * cs;
    khm_int32 rv;

    if (!kcdb_credset_is_credset(credset))
        return KHM_ERROR_INVALID_PARAM;

    cs = (kcdb_credset *) credset;

    EnterCriticalSection(&cs->cs);
    if (cs->seal_count > 0) {
        cs->seal_count--;
        rv = KHM_ERROR_SUCCESS;
    } else {
        rv = KHM_ERROR_INVALID_OPERATION;
    }
    LeaveCriticalSection(&cs->cs);

    return rv;
}

/* These are protected with cs_credset */
static void * _creds_comp_rock = NULL;
static kcdb_cred_comp_func _creds_comp_func = NULL;

/* Need cs_credset when calling this function. */
int __cdecl
kcdb_creds_comp_wrapper(const void * a, const void * b)
{
    return (*_creds_comp_func)((khm_handle) ((kcdb_credset_credref *)a)->cred,
                               (khm_handle) ((kcdb_credset_credref *)b)->cred,
                               _creds_comp_rock);
}

KHMEXP khm_int32 KHMAPI
kcdb_credset_sort(khm_handle credset,
		  kcdb_cred_comp_func comp,
		  void * rock)
{
    khm_int32 code = KHM_ERROR_SUCCESS;
    kcdb_credset * cs;

    if(!kcdb_credset_is_credset(credset))
        return KHM_ERROR_INVALID_PARAM;

    cs = (kcdb_credset *) credset;

    if (kcdb_credset_is_sealed(cs))
        return KHM_ERROR_INVALID_OPERATION;

    EnterCriticalSection(&(cs->cs));

#ifdef DEBUG
    assert(!(cs->flags & KCDB_CREDSET_FLAG_ENUM));
#endif

    EnterCriticalSection(&cs_credset);

    _creds_comp_rock = rock;
    _creds_comp_func = comp;

    qsort(cs->clist, cs->nclist,
	  sizeof(kcdb_credset_credref), kcdb_creds_comp_wrapper);

    LeaveCriticalSection(&cs_credset);

    LeaveCriticalSection(&(cs->cs));
    return code;
}

KHMEXP khm_int32 KHMAPI
kcdb_cred_comp_generic(khm_handle cred1,
		       khm_handle cred2,
		       void * rock)
{
    kcdb_cred_comp_order * o = (kcdb_cred_comp_order *) rock;
    int i;
    khm_int32 r = 0;
    khm_int32 f1, f2;
    khm_int32 t1, t2;
    khm_int32 pt;

    for(i=0; i<o->nFields; i++) {
        if (o->fields[i].order & KCDB_CRED_COMP_INITIAL_FIRST) {

            if (o->fields[i].attrib == KCDB_ATTR_TYPE_NAME ||
                o->fields[i].attrib == KCDB_ATTR_TYPE) {

                kcdb_cred_get_type(cred1, &t1);
                kcdb_cred_get_type(cred2, &t2);
                kcdb_identity_get_type(&pt);

                if (t1 == t2)
                    r = 0;
                else if (t1 == pt)
                    r = -1;
                else if (t2 == pt)
                    r = 1;
                else
                    r = 0;

            } else {

                kcdb_cred_get_flags(cred1, &f1);
                kcdb_cred_get_flags(cred2, &f2);

                if (((f1 ^ f2) & KCDB_CRED_FLAG_INITIAL) == 0)
                    r = 0;
                else if (f1 & KCDB_CRED_FLAG_INITIAL)
                    r = -1;
                else
                    r = 1;

            }

        } else {
            r = 0;
        }

        if (r == 0)
            r = kcdb_creds_comp_attr(cred1,cred2,o->fields[i].attrib);

        if(r != 0) {
            if(o->fields[i].order & KCDB_CRED_COMP_DECREASING)
                r = -r;
            break;
        }
    }

    return r;
}
