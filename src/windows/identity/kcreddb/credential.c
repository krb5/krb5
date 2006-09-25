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

/* cs_creds protects the *collection* of credentials, while l_creds
   protects the *contents* of individual credentials. */
CRITICAL_SECTION cs_creds;
kcdb_cred * kcdb_creds = NULL;

/* a read lock must be obtained when querying any existing credential.
   a write lock must be obtained when modifying any existing credential.
   */
RWLOCK l_creds;

/* serial number */
khm_ui_8 kcdb_cred_id = 0;

void kcdb_cred_init(void)
{
    InitializeCriticalSection(&cs_creds);
    InitializeRwLock(&l_creds);
    kcdb_cred_id = 0;
}

void kcdb_cred_exit(void)
{
    /*TODO: Free the credentials */
    DeleteCriticalSection(&cs_creds);
    DeleteRwLock(&l_creds);
}

/*! \internal

    can be called by kcdb_cred_dup with a write lock on l_creds and in other
    places with a read lock on l_creds.  New credentials must be creatable while
    holding either lock. */
KHMEXP khm_int32 KHMAPI 
kcdb_cred_create(const wchar_t *   name, 
                 khm_handle  identity,
                 khm_int32   cred_type,
                 khm_handle * result) 
{
    kcdb_cred * cred;
    size_t cb_name;

    if(!name || !result ||
        FAILED(StringCbLength(name, KCDB_CRED_MAXCB_NAME, &cb_name)) ||
        KHM_FAILED(kcdb_credtype_get_info(cred_type, NULL)) ||
        KHM_FAILED(kcdb_identity_hold(identity))) {
        return KHM_ERROR_INVALID_PARAM;
    }

    cb_name += sizeof(wchar_t);

    cred = PMALLOC(sizeof(kcdb_cred));
    ZeroMemory(cred, sizeof(kcdb_cred));

    cred->magic = KCDB_CRED_MAGIC;
    cred->identity = identity;
    cred->name = PMALLOC(cb_name);
    StringCbCopy(cred->name, cb_name, name);
    cred->type = cred_type;

    cred->refcount = 1; /* initially held */
    
    LINIT(cred);

    kcdb_buf_new(&cred->buf, KCDB_ATTR_MAX_ID + 1);

    /* Not obtaining a write lock on l_cred on purpose.
       Well, because no one should be referencing this credential until
       this function returns. */
    EnterCriticalSection(&cs_creds);
    cred->id = kcdb_cred_id++;
    LPUSH(&kcdb_creds, cred);
    LeaveCriticalSection(&cs_creds);

    *result = cred;

    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32 KHMAPI kcdb_cred_update(khm_handle vdest,
                                         khm_handle vsrc)
{
    khm_int32 rv = KHM_ERROR_EQUIVALENT;
    kcdb_cred * src;
    kcdb_cred * dest;
    kcdb_type * t;
    kcdb_attrib * a;
    void * srcbuf;
    void * destbuf;
    khm_size cbsrcbuf;
    khm_size cbdestbuf;

    int i;

    kcdb_cred_lock_write();

    if(!kcdb_cred_is_active_cred(vsrc) ||
       !kcdb_cred_is_active_cred(vdest))
        goto _exit;

    src = (kcdb_cred *) vsrc;
    dest = (kcdb_cred *) vdest;

    for(i=0;i<KCDB_ATTR_MAX_ID;i++) {
        if(kcdb_cred_val_exist(src, i)) {
            /*NOTE: the logic here has to reflect the logic in
              kcdb_cred_set_attr() */
            if(KHM_FAILED(kcdb_attrib_get_info(i, &a)))
                continue;

            if((a->flags & KCDB_ATTR_FLAG_COMPUTED) ||
                KHM_FAILED(kcdb_type_get_info(a->type, &t))) {
                kcdb_attrib_release_info(a);
                continue;
            }

            srcbuf = kcdb_cred_buf_get(src,i);
            cbsrcbuf = kcdb_cred_buf_size(src, i);

            if(kcdb_cred_val_exist(dest, i)) {
                destbuf = kcdb_cred_buf_get(dest, i);
                cbdestbuf = kcdb_cred_buf_size(dest, i);

                if(!t->comp(srcbuf, cbsrcbuf, destbuf, cbdestbuf))
                    goto _skip_copy;
            }

            kcdb_buf_set_value(&dest->buf, i, i, srcbuf, cbsrcbuf);
            rv = KHM_ERROR_SUCCESS;

	_skip_copy:
            kcdb_attrib_release_info(a);
            kcdb_type_release_info(t);
        } else {
	    if (KHM_FAILED(kcdb_attrib_get_info(i, &a)))
		continue;

	    if (!(a->flags & KCDB_ATTR_FLAG_COMPUTED) &&
		(a->flags & KCDB_ATTR_FLAG_TRANSIENT) &&
		kcdb_cred_val_exist(dest, i)) {
		kcdb_buf_set_value(&dest->buf, i, i, NULL, 0);

		rv = KHM_ERROR_SUCCESS;
	    }

	    kcdb_attrib_release_info(a);
	}
    }

    if (dest->flags != src->flags) {
        khm_int32 old_flags;

        old_flags = dest->flags;

        dest->flags = (src->flags & ~KCDB_CRED_FLAGMASK_ADDITIVE) |
            ((src->flags | dest->flags) & KCDB_CRED_FLAGMASK_ADDITIVE);

        if (dest->flags != old_flags)
            rv = KHM_ERROR_SUCCESS;
    }

 _exit:
    kcdb_cred_unlock_write();
    return rv;
}

KHMEXP khm_int32 KHMAPI kcdb_cred_dup(
    khm_handle vcred,
    khm_handle * pnewcred)
{
    khm_int32 code = KHM_ERROR_SUCCESS;
    kcdb_cred * cred;
    kcdb_cred * newcred;
    khm_handle vnewcred;

    if(!pnewcred)
        return KHM_ERROR_INVALID_PARAM;

    *pnewcred = NULL;

    kcdb_cred_lock_write();

    if(!kcdb_cred_is_active_cred(vcred)) {
        code = KHM_ERROR_INVALID_PARAM;
        goto _exit;
    }

    cred = (kcdb_cred *) vcred;

    if(KHM_FAILED(kcdb_cred_create(cred->name,
                                   cred->identity,
                                   cred->type,
                                   &vnewcred))) 
    {
        code = KHM_ERROR_UNKNOWN;
        goto _exit;
    }

    newcred = (kcdb_cred *) vnewcred;

    newcred->flags = cred->flags;

    kcdb_buf_dup(&newcred->buf, &cred->buf);

    /* newcred is already held from the call to kcdb_cred_create */
    *pnewcred = (khm_handle) newcred;

_exit:
    kcdb_cred_unlock_write();
    return code;
}

KHMEXP khm_int32 KHMAPI kcdb_cred_get_serial(
    khm_handle vcred,
    khm_ui_8 * pserial)
{
    kcdb_cred * c;

    if(!pserial)
        return KHM_ERROR_INVALID_PARAM;

    kcdb_cred_lock_read();

    if(!kcdb_cred_is_active_cred(vcred)) {
        kcdb_cred_unlock_read();
        return KHM_ERROR_INVALID_PARAM;
    }

    c = (kcdb_cred *) vcred;

    *pserial = c->id;

    kcdb_cred_unlock_read();

    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32 KHMAPI kcdb_cred_set_identity(
    khm_handle vcred,
    khm_handle id)
{
    kcdb_cred * c;

    if(!kcdb_is_identity(id))
        return KHM_ERROR_INVALID_PARAM;

    kcdb_cred_lock_write();
    if(!kcdb_cred_is_active_cred(vcred)) {
        kcdb_cred_unlock_write();
        return KHM_ERROR_INVALID_PARAM;
    }

    c = (kcdb_cred *) vcred;

    if(c->identity) {
        kcdb_identity_release((khm_handle) c->identity);
    }
    kcdb_identity_hold(id);
    c->identity = (kcdb_identity *) id;

    kcdb_cred_unlock_write();

    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32 KHMAPI kcdb_cred_get_type(
    khm_handle vcred,
    khm_int32 * type)
{
    kcdb_cred * c;

    if(!type)
        return KHM_ERROR_INVALID_PARAM;

    kcdb_cred_lock_read();

    if(!kcdb_cred_is_active_cred(vcred)) {
        kcdb_cred_unlock_read();
        return KHM_ERROR_INVALID_PARAM;
    }

    c = (kcdb_cred *) vcred;

    *type = c->type;

    kcdb_cred_unlock_read();

    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32 KHMAPI kcdb_cred_set_attrib(
    khm_handle cred, 
    const wchar_t * name, 
    void * buffer, 
    khm_size cbbuf)
{
    khm_int32 attr_id = -1;

    if(KHM_FAILED(kcdb_attrib_get_id(name, &attr_id)))
        return KHM_ERROR_INVALID_PARAM;

    return kcdb_cred_set_attr(
        cred,
        attr_id,
        buffer,
        cbbuf);
}

KHMEXP khm_int32 KHMAPI kcdb_cred_set_attr(
    khm_handle vcred, 
    khm_int32 attr_id, 
    void * buffer, 
    khm_size cbbuf)
{
    kcdb_cred * cred;
    kcdb_type * type = NULL;
    kcdb_attrib * attrib = NULL;
    khm_size cbdest;
    khm_int32 code = KHM_ERROR_SUCCESS;

    if(attr_id < 0 || attr_id > KCDB_ATTR_MAX_ID)
        return KHM_ERROR_INVALID_PARAM;

    kcdb_cred_lock_write();

    if(!kcdb_cred_is_active_cred(vcred)) {
        kcdb_cred_unlock_write();
        return KHM_ERROR_INVALID_PARAM;
    }

    cred = (kcdb_cred *) vcred;

    if(KHM_FAILED(kcdb_attrib_get_info(attr_id, &attrib))) {
        kcdb_cred_unlock_write();
        return KHM_ERROR_INVALID_PARAM;
    }

    if(attrib->flags & KCDB_ATTR_FLAG_COMPUTED)
    {
        kcdb_cred_unlock_write();
        kcdb_attrib_release_info(attrib);
        return KHM_ERROR_INVALID_OPERATION;
    }

    if (buffer == 0) {
        /* we are removing the value */
        kcdb_buf_alloc(&cred->buf, attr_id, attr_id, 0);
        code = KHM_ERROR_SUCCESS;
        goto _exit;
    }

    if(KHM_FAILED(kcdb_type_get_info(attrib->type, &type))) {
        kcdb_cred_unlock_write();
        kcdb_attrib_release_info(attrib);
        return KHM_ERROR_INVALID_PARAM;
    }

    if(!(type->isValid(buffer,cbbuf))) {
        code = KHM_ERROR_TYPE_MISMATCH;
        goto _exit;
    }

    if((type->dup(buffer, cbbuf, NULL, &cbdest)) != KHM_ERROR_TOO_LONG) {
        code = KHM_ERROR_INVALID_PARAM;
        goto _exit;
    }

    kcdb_buf_alloc(&cred->buf, attr_id, attr_id, cbdest);
    if(!kcdb_cred_buf_exist(cred, attr_id)) {
        code = KHM_ERROR_NO_RESOURCES;
        goto _exit;
    }

    if(KHM_FAILED(code =
        type->dup(buffer, cbbuf, kcdb_cred_buf_get(cred,attr_id), &cbdest))) 
    {
        kcdb_buf_alloc(&cred->buf, attr_id, attr_id, 0);
        goto _exit;
    }

    kcdb_buf_set_value_flag(&cred->buf, attr_id);

_exit:
    kcdb_cred_unlock_write();

    if(attrib)
        kcdb_attrib_release_info(attrib);
    if(type)
        kcdb_type_release_info(type);

    return code;
}

KHMEXP khm_int32 KHMAPI kcdb_cred_get_attrib(
    khm_handle cred, 
    const wchar_t * name, 
    khm_int32 * attr_type,
    void * buffer, 
    khm_size * cbbuf) 
{
    khm_int32 attr_id = -1;

    if(KHM_FAILED(kcdb_attrib_get_id(name, &attr_id)))
        return KHM_ERROR_NOT_FOUND;

    return kcdb_cred_get_attr(
        cred,
        attr_id,
        attr_type,
        buffer,
        cbbuf);
}

KHMEXP khm_int32 KHMAPI kcdb_cred_get_attrib_string(
    khm_handle cred, 
    const wchar_t * name, 
    wchar_t * buffer, 
    khm_size * cbbuf,
    khm_int32 flags) 
{
    khm_int32 attr_id = -1;

    if(KHM_FAILED(kcdb_attrib_get_id(name, &attr_id)))
        return KHM_ERROR_NOT_FOUND;

    return kcdb_cred_get_attr_string(
        cred,
        attr_id,
        buffer,
        cbbuf,
        flags);
}

KHMEXP khm_int32 KHMAPI 
kcdb_cred_get_attr(khm_handle vcred, 
                   khm_int32 attr_id,
                   khm_int32 * attr_type,
                   void * buffer, 
                   khm_size * pcbbuf)
{
    khm_int32 code = KHM_ERROR_SUCCESS;
    kcdb_cred * cred = NULL;
    kcdb_attrib * attrib = NULL;
    kcdb_type * type = NULL;

    if(attr_id < 0 || attr_id > KCDB_ATTR_MAX_ID)
        return KHM_ERROR_INVALID_PARAM;

    if(KHM_FAILED(kcdb_attrib_get_info(attr_id, &attrib))) {
        return KHM_ERROR_INVALID_PARAM;
    }

    if(KHM_FAILED(kcdb_type_get_info(attrib->type, &type))) {
        kcdb_attrib_release_info(attrib);
        return KHM_ERROR_UNKNOWN;
    }

    if(attr_type)
        *attr_type = attrib->type;

    kcdb_cred_lock_read();
    if(!kcdb_cred_is_active_cred(vcred)) {
        code = KHM_ERROR_INVALID_PARAM;
        goto _exit;
    }

    cred = (kcdb_cred *) vcred;

    if(!buffer && !pcbbuf) {
        /* in this case the caller is only trying to determine if the
            field contains data.  We assume that computed fields are
            always non-null. */
        code = (kcdb_cred_val_exist(cred, attr_id) ||
            (attrib->flags & KCDB_ATTR_FLAG_COMPUTED))?KHM_ERROR_SUCCESS:KHM_ERROR_NOT_FOUND;
        goto _exit;
    }

    if(attrib->flags & KCDB_ATTR_FLAG_COMPUTED) {
        code = attrib->compute_cb(
            vcred,
            attr_id,
            buffer,
            pcbbuf);
    } else if (kcdb_cred_val_exist(cred, attr_id)) {
        code = type->dup(
            kcdb_cred_buf_get(cred, attr_id),
            kcdb_cred_buf_size(cred, attr_id),
            buffer,
            pcbbuf);
    } else {
        code = KHM_ERROR_NOT_FOUND;
    }

_exit:
    kcdb_cred_unlock_read();
    if(type)
        kcdb_type_release_info(type);
    if(attrib)
        kcdb_attrib_release_info(attrib);

    return code;
}

KHMEXP khm_int32 KHMAPI kcdb_cred_get_attr_string(
    khm_handle vcred, 
    khm_int32 attr_id,
    wchar_t * buffer, 
    khm_size * pcbbuf,
    khm_int32 flags)
{
    khm_int32 code = KHM_ERROR_SUCCESS;
    kcdb_cred * cred = NULL;
    kcdb_attrib * attrib = NULL;
    kcdb_type * type = NULL;

    if(attr_id < 0 || attr_id > KCDB_ATTR_MAX_ID)
        return KHM_ERROR_INVALID_PARAM;

    if(KHM_FAILED(kcdb_attrib_get_info(attr_id, &attrib))) {
        code = KHM_ERROR_INVALID_PARAM;
        goto _exit_nolock;
    }

    if(KHM_FAILED(kcdb_type_get_info(attrib->type, &type))) {
        code = KHM_ERROR_UNKNOWN;
        goto _exit_nolock;
    }

    kcdb_cred_lock_read();
    if(!kcdb_cred_is_active_cred(vcred)) {
        code = KHM_ERROR_INVALID_PARAM;
        goto _exit;
    }

    cred = (kcdb_cred *) vcred;

    if(!buffer && !pcbbuf) {
        /* in this case the caller is only trying to determine if the
            field contains data.  We assume that computed fields are
            always non-null. */
        code = (kcdb_cred_val_exist(cred, attr_id) ||
            (attrib->flags & KCDB_ATTR_FLAG_COMPUTED))?KHM_ERROR_SUCCESS:KHM_ERROR_NOT_FOUND;
        goto _exit;
    }

    if(attrib->flags & KCDB_ATTR_FLAG_COMPUTED) {
        void * buf;
        khm_size cbbuf;

        code = attrib->compute_cb(vcred,
                                  attr_id,
                                  NULL,
                                  &cbbuf);
        if(code == KHM_ERROR_TOO_LONG) {
            wchar_t vbuf[KCDB_MAXCCH_NAME];

            if (cbbuf < sizeof(vbuf))
                buf = vbuf;
            else
                buf = PMALLOC(cbbuf);

            code = attrib->compute_cb(vcred,
                                      attr_id,
                                      buf,
                                      &cbbuf);
            if(KHM_SUCCEEDED(code)) {
                code = type->toString(buf,
                                      cbbuf,
                                      buffer,
                                      pcbbuf,
                                      flags);
            }

            if (buf != vbuf)
                PFREE(buf);
        }
    } else {
        if(kcdb_cred_buf_exist(cred, attr_id)) {
            code = type->toString(
                kcdb_cred_buf_get(cred, attr_id),
                kcdb_cred_buf_size(cred, attr_id),
                buffer,
                pcbbuf,
                flags);
        } else
            code = KHM_ERROR_NOT_FOUND;
    }

 _exit:
    kcdb_cred_unlock_read();
 _exit_nolock:
    if(type)
        kcdb_type_release_info(type);
    if(attrib)
        kcdb_attrib_release_info(attrib);

    return code;
}


KHMEXP khm_int32 KHMAPI kcdb_cred_get_name(
    khm_handle vcred, 
    wchar_t * buffer, 
    khm_size * cbbuf)
{
    khm_int32 code = KHM_ERROR_SUCCESS;
    kcdb_cred * cred = NULL;
    size_t cbsize;

    if(!cbbuf)
        return KHM_ERROR_INVALID_PARAM;

    kcdb_cred_lock_read();
    
    if(!kcdb_cred_is_active_cred(vcred)) {
        code = KHM_ERROR_INVALID_PARAM;
        goto _exit;
    }

    cred = (kcdb_cred *) vcred;

    if(FAILED(StringCbLength(cred->name, KCDB_CRED_MAXCB_NAME, &cbsize))) {
        code = KHM_ERROR_UNKNOWN;
        goto _exit;
    }

    cbsize += sizeof(wchar_t);

    if(!buffer || *cbbuf < cbsize) {
        *cbbuf = cbsize;
        code = KHM_ERROR_TOO_LONG;
        goto _exit;
    }

    StringCbCopy(buffer, *cbbuf, cred->name);

    *cbbuf = cbsize;

_exit:

    kcdb_cred_unlock_read();
    return code;
}

KHMEXP khm_int32 KHMAPI kcdb_cred_get_identity(
    khm_handle vcred, 
    khm_handle * identity)
{
    khm_int32 code = KHM_ERROR_SUCCESS;
    kcdb_cred * cred;

    if(!identity)
        return KHM_ERROR_INVALID_PARAM;

    kcdb_cred_lock_read();

    if(!kcdb_cred_is_active_cred(vcred)) {
        code = KHM_ERROR_INVALID_PARAM;
        goto _exit;
    }

    cred = (kcdb_cred *) vcred;

    kcdb_identity_hold((khm_handle) cred->identity);

    *identity = cred->identity;
    
_exit:
    kcdb_cred_unlock_read();
    return code;
}

KHMEXP khm_int32 KHMAPI kcdb_cred_hold(khm_handle vcred)
{
    khm_int32 code = KHM_ERROR_SUCCESS;
    kcdb_cred * cred;

    kcdb_cred_lock_write();

    if(!kcdb_cred_is_cred(vcred)) {
        code = KHM_ERROR_INVALID_PARAM;
        goto _exit;
    }

    cred = (kcdb_cred *) vcred;

    cred->refcount++;

_exit:
    kcdb_cred_unlock_write();
    return code;
}

KHMEXP khm_int32 KHMAPI kcdb_cred_release(khm_handle vcred)
{
    khm_int32 code = KHM_ERROR_SUCCESS;
    kcdb_cred * cred;

    kcdb_cred_lock_write();

    if(!kcdb_cred_is_cred(vcred)) {
        code = KHM_ERROR_INVALID_PARAM;
        goto _exit;
    }

    cred = (kcdb_cred *) vcred;

    cred->refcount--;

_exit:
    kcdb_cred_unlock_write();

    kcdb_cred_check_and_delete(vcred);
    
    return code;
}

void kcdb_cred_check_and_delete(khm_handle vcred)
{
    kcdb_cred * cred;

    kcdb_cred_lock_read();
    if(!kcdb_cred_is_cred(vcred)) {
        goto _exit;
    }

    cred = (kcdb_cred *) vcred;

    if(cred->refcount)
        goto _exit;

    kcdb_cred_unlock_read();
    kcdb_cred_lock_write();
    if(!kcdb_cred_is_cred(vcred)) {
        /* did we lose the race? */
        goto _exit2;
    }

    cred->magic = 0; /* no longer a cred */
    kcdb_identity_release(cred->identity);

    EnterCriticalSection(&cs_creds);
    LDELETE(&kcdb_creds, cred);
    LeaveCriticalSection(&cs_creds);

    kcdb_buf_delete(&cred->buf);
    PFREE(cred->name);
    PFREE(cred);

    /*TODO: notifications */

_exit2:
    kcdb_cred_unlock_write();
    return;

_exit:
    kcdb_cred_unlock_read();
}

KHMEXP khm_int32 KHMAPI kcdb_cred_delete(khm_handle vcred)
{
    khm_int32 code = KHM_ERROR_SUCCESS;
    kcdb_cred * cred;

    kcdb_cred_lock_write();

    if(!kcdb_cred_is_active_cred(vcred)) {
        code = KHM_ERROR_INVALID_PARAM;
        goto _exit;
    }

    cred = (kcdb_cred *) vcred;

    cred->flags |= KCDB_CRED_FLAG_DELETED;

_exit:
    kcdb_cred_unlock_write();

    kcdb_cred_check_and_delete(vcred);

    return code;
}

KHMEXP khm_int32 KHMAPI 
kcdb_creds_comp_attrib(khm_handle cred1, 
                       khm_handle cred2, 
                       const wchar_t * name)
{
    khm_int32 attr_id;

    if(KHM_FAILED(kcdb_attrib_get_id(name, &attr_id)))
        return 0;

    return kcdb_creds_comp_attr(cred1, cred2, attr_id);
}

KHMEXP khm_int32 KHMAPI 
kcdb_creds_comp_attr(khm_handle vcred1, 
                     khm_handle vcred2, 
                     khm_int32 attr_id)
{
    khm_int32 code = 0;
    kcdb_cred * cred1;
    kcdb_cred * cred2;
    kcdb_attrib * attrib = NULL;
    kcdb_type * type = NULL;

    if(attr_id < 0 || attr_id > KCDB_ATTR_MAX_ID)
        return 0;

    cred1 = (kcdb_cred *) vcred1;
    cred2 = (kcdb_cred *) vcred2;

    kcdb_cred_lock_read();
    if(
        !kcdb_cred_is_active_cred(vcred1) ||
        !kcdb_cred_is_active_cred(vcred2))
        goto _exit;

    cred1 = (kcdb_cred *) vcred1;
    cred2 = (kcdb_cred *) vcred2;

    if(KHM_FAILED(kcdb_attrib_get_info(attr_id, &attrib)))
        goto _exit;

    if(!(attrib->flags & KCDB_ATTR_FLAG_COMPUTED)) {
        int nc = 0;

        if(!kcdb_cred_val_exist(cred1, attr_id)) {
            code = -1;
            nc = 1;
        }
        if(!kcdb_cred_val_exist(cred2, attr_id)) {
            code += 1;
            nc = 1;
        }

        if(nc)
            goto _exit;
    }

    if(KHM_FAILED(kcdb_type_get_info(attrib->type, &type)))
        goto _exit;

    if(attrib->flags & KCDB_ATTR_FLAG_COMPUTED) {
        khm_octet  vbuf[KCDB_MAXCB_NAME * 2];
        void * buf1 = NULL;
        void * buf2 = NULL;
        khm_size cb1;
        khm_size cb2;

        code = 0;

        if(attrib->compute_cb(vcred1, attr_id, 
                              NULL, &cb1) != KHM_ERROR_TOO_LONG)
            goto _exit_1;

        if(attrib->compute_cb(vcred2, attr_id, 
                              NULL, &cb2) != KHM_ERROR_TOO_LONG)
            goto _exit_1;

        if(cb1) {
            if (cb1 < sizeof(vbuf))
                buf1 = vbuf;
            else
                buf1 = PMALLOC(cb1);

            if(KHM_FAILED(attrib->compute_cb(vcred1, attr_id, buf1, &cb1)))
                goto _exit_1;
        }

        if(cb2) {
            if (cb1 + cb2 < sizeof(vbuf))
                buf2 = vbuf + cb1;
            else
                buf2 = PMALLOC(cb2);

            if(KHM_FAILED(attrib->compute_cb(vcred2, attr_id, buf2, &cb2)))
                goto _exit_1;
        }

        code = type->comp(buf1, cb1,
                          buf2, cb2);
_exit_1:
        if(buf1 && (buf1 < (void *)vbuf || 
                    buf1 >= (void*)(vbuf + sizeof(vbuf))))
            PFREE(buf1);
        if(buf2 && (buf2 < (void *)vbuf ||
                    buf2 >= (void *)(vbuf + sizeof(vbuf))))
            PFREE(buf2);
    } else {
        code = type->comp(
            kcdb_cred_buf_get(cred1, attr_id),
            kcdb_cred_buf_size(cred1, attr_id),
            kcdb_cred_buf_get(cred2, attr_id),
            kcdb_cred_buf_size(cred2, attr_id));
    }

_exit:
    kcdb_cred_unlock_read();
    if(attrib)
        kcdb_attrib_release_info(attrib);
    if(type)
        kcdb_type_release_info(type);
    return code;
}

KHMEXP khm_int32 KHMAPI 
kcdb_creds_is_equal(khm_handle vcred1,
                    khm_handle vcred2)
{
    khm_int32 code = 0;
    kcdb_cred * cred1;
    kcdb_cred * cred2;

    kcdb_cred_lock_read();
    if(!kcdb_cred_is_active_cred(vcred1) ||
       !kcdb_cred_is_active_cred(vcred2)) {

        code = FALSE;
        goto _exit;

    }

    if(vcred1 == vcred2) {

        code = TRUE;
        goto _exit;

    }

    cred1 = vcred1;
    cred2 = vcred2;

    if(cred1->identity == cred2->identity &&
       cred1->type == cred2->type &&
       !wcscmp(cred1->name, cred2->name)) {

        kcdb_credtype * type;

        code = TRUE;

        if (KHM_SUCCEEDED(kcdb_credtype_get_info(cred1->type, &type))) {
            if (type->is_equal &&
                (*type->is_equal)(vcred1, vcred2, NULL))
                code = 0;

            kcdb_credtype_release_info(type);
        }
    }

_exit:
    kcdb_cred_unlock_read();
    return code;
}

KHMEXP khm_int32 KHMAPI 
kcdb_cred_get_flags(khm_handle vcred,
                    khm_int32 * pflags)
{
    khm_int32 f;
    khm_int32 rv = KHM_ERROR_SUCCESS;
    kcdb_cred * cred;
    int release_lock = TRUE;

    if (pflags == NULL)
        return KHM_ERROR_INVALID_PARAM;

    kcdb_cred_lock_read();
    if (!kcdb_cred_is_active_cred(vcred)) {
        *pflags = 0;
        rv = KHM_ERROR_INVALID_PARAM;
        goto _exit;
    }

    cred = vcred;
    f = cred->flags;

    /* Update flags if necessary */

    if (!(f & KCDB_CRED_FLAG_EXPIRED) && 
        kcdb_cred_buf_exist(cred, KCDB_ATTR_EXPIRE)) {

        FILETIME ftc;
            
        GetSystemTimeAsFileTime(&ftc);
        if (CompareFileTime(&ftc, ((FILETIME *) 
                                   kcdb_cred_buf_get(cred, KCDB_ATTR_EXPIRE)))
            >= 0)
            f |= KCDB_CRED_FLAG_EXPIRED;
    }

#if 0
    /* Commented out: if the credential has expired, then checking the
       renewable time is not useful */
    if (!(f & KCDB_CRED_FLAG_INVALID)) {
        if (f & KCDB_CRED_FLAG_RENEWABLE) {
            if (kcdb_cred_buf_exist(cred, KCDB_ATTR_RENEW_EXPIRE)) {
                FILETIME ftc;

                GetSystemTimeAsFileTime(&ftc);
                if (CompareFileTime(&ftc, ((FILETIME *)
                                           kcdb_cred_buf_get(cred, KCDB_ATTR_RENEW_EXPIRE))) >= 0)
                    f |= KCDB_CRED_FLAG_INVALID;
            }
        } else {
            if (f & KCDB_CRED_FLAG_EXPIRED)
                f |= KCDB_CRED_FLAG_INVALID;
        }
    }

    /* Commented out: this is a read operation.  We shouldn't attempt
       to lock for writing */
    if (f != cred->flags) {
        kcdb_cred_unlock_read();
        kcdb_cred_lock_write();
        /* Did we lose a race? */
        if (kcdb_cred_is_active_cred(vcred))
            cred->flags = f;
        else {
            rv = KHM_ERROR_INVALID_PARAM;
            f = 0;
        }
        kcdb_cred_unlock_write();
        release_lock = FALSE;
    }
#endif

    *pflags = f;

 _exit:
    if (release_lock)
        kcdb_cred_unlock_read();

    return rv;
}

KHMEXP khm_int32 KHMAPI kcdb_cred_set_flags(
    khm_handle vcred,
    khm_int32 flags,
    khm_int32 mask)
{
    khm_int32 rv = KHM_ERROR_SUCCESS;
    kcdb_cred * cred;

    kcdb_cred_lock_write();
    if(!kcdb_cred_is_active_cred(vcred)) {
        rv = KHM_ERROR_INVALID_PARAM;
        goto _exit;
    }

    cred = vcred;

    flags &= ~(KCDB_CRED_FLAG_DELETED);
    mask &= ~(KCDB_CRED_FLAG_DELETED);

    cred->flags =
        (cred->flags & (~mask)) |
        (flags & mask);

 _exit:
    kcdb_cred_unlock_write();
    return rv;
}
