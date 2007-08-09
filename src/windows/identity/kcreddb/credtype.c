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

CRITICAL_SECTION cs_credtype;
kcdb_credtype_i ** kcdb_credtype_tbl = NULL;
kcdb_credtype_i * kcdb_credtypes = NULL;

void kcdb_credtype_init(void)
{
    InitializeCriticalSection(&cs_credtype);
    kcdb_credtypes = NULL;

    kcdb_credtype_tbl = PMALLOC(sizeof(kcdb_credtype_i *) * (KCDB_CREDTYPE_MAX_ID+1));
    ZeroMemory(kcdb_credtype_tbl, sizeof(kcdb_credtype_i *) * (KCDB_CREDTYPE_MAX_ID+1));
}

void kcdb_credtype_exit(void)
{
    /*TODO:Free up the cred types */
    PFREE(kcdb_credtype_tbl);
    DeleteCriticalSection(&cs_credtype);
}

/* Called with cs_credtype held */
void kcdb_credtype_check_and_delete(khm_int32 id)
{
    kcdb_credtype_i * ict;
    ict = kcdb_credtype_tbl[id];
    if(!ict)
        return;

    if((ict->flags & KCDB_CTI_FLAG_DELETED) &&
        !ict->refcount)
    {
        kcdb_credtype_tbl[id] = NULL;
        LDELETE(&kcdb_credtypes, ict);

        PFREE(ict->ct.name);
        if(ict->ct.short_desc)
            PFREE(ict->ct.short_desc);
        if(ict->ct.long_desc)
            PFREE(ict->ct.long_desc);
        if(ict->ct.sub)
            kmq_delete_subscription(ict->ct.sub);

        PFREE(ict);
    }
}

KHMEXP khm_int32 KHMAPI 
kcdb_credtype_register(const kcdb_credtype * type, khm_int32 * new_id) 
{
    khm_int32 id;
    kcdb_credtype_i * ict;
    size_t cb_name;
    size_t cb_short_desc;
    size_t cb_long_desc;
    int i;

    if(!type)
        return KHM_ERROR_INVALID_PARAM;

    if(type->id >= KCDB_CREDTYPE_MAX_ID)
        return KHM_ERROR_INVALID_PARAM;

    if(type->name) {
        if(FAILED(StringCbLength(type->name, KCDB_MAXCB_NAME, &cb_name)))
            return KHM_ERROR_TOO_LONG;
        cb_name += sizeof(wchar_t);
    } else
        return KHM_ERROR_INVALID_PARAM;

    if(type->short_desc) {
        if(FAILED(StringCbLength(type->short_desc, KCDB_MAXCB_SHORT_DESC, &cb_short_desc)))
            return KHM_ERROR_TOO_LONG;
        cb_short_desc += sizeof(wchar_t);
    } else
        cb_short_desc = 0;

    if(type->long_desc) {
        if(FAILED(StringCbLength(type->long_desc, KCDB_MAXCB_LONG_DESC, &cb_long_desc)))
            return KHM_ERROR_TOO_LONG;
        cb_long_desc += sizeof(wchar_t);
    } else
        cb_long_desc = 0;

    if(type->sub == NULL)
        return KHM_ERROR_INVALID_PARAM;

    EnterCriticalSection(&cs_credtype);

    if(type->id < 0) {
        if(KHM_FAILED(kcdb_credtype_get_next_free_id(&id))) {
            LeaveCriticalSection(&cs_credtype);
            return KHM_ERROR_NO_RESOURCES;
        }
    }
    else
        id = type->id;

    if(kcdb_credtype_tbl[id]) {
        LeaveCriticalSection(&cs_credtype);
        return KHM_ERROR_DUPLICATE;
    }

    for(i=0;i<=KCDB_CREDTYPE_MAX_ID;i++) {
        if(kcdb_credtype_tbl[i] && !wcscmp(kcdb_credtype_tbl[i]->ct.name, type->name)) {
            LeaveCriticalSection(&cs_credtype);
            return KHM_ERROR_DUPLICATE;
        }
    }

    ict = PMALLOC(sizeof(kcdb_credtype_i));
    ZeroMemory(ict, sizeof(kcdb_credtype_i));

    ict->ct.name = PMALLOC(cb_name);
    StringCbCopy(ict->ct.name, cb_name, type->name);

    if(cb_short_desc) {
        ict->ct.short_desc = PMALLOC(cb_short_desc);
        StringCbCopy(ict->ct.short_desc, cb_short_desc, type->short_desc);
    }

    if(cb_long_desc) {
        ict->ct.long_desc = PMALLOC(cb_long_desc);
        StringCbCopy(ict->ct.long_desc, cb_long_desc, type->long_desc);
    }

    ict->ct.id = id;

    ict->ct.icon = type->icon;

    ict->ct.sub = type->sub;

    ict->ct.is_equal = type->is_equal;

    kcdb_credtype_tbl[id] = ict;

    LPUSH(&kcdb_credtypes, ict);

    LeaveCriticalSection(&cs_credtype);

    kcdb_credtype_post_message(KCDB_OP_INSERT, &(ict->ct));

    if (new_id)
        *new_id = id;

    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32 KHMAPI kcdb_credtype_get_info(
    khm_int32 id, 
    kcdb_credtype ** type)
{
    int found = 0;

    if(id < 0 || id > KCDB_CREDTYPE_MAX_ID)
        return KHM_ERROR_INVALID_PARAM;

    EnterCriticalSection(&cs_credtype);
    if(kcdb_credtype_tbl[id] && 
        !(kcdb_credtype_tbl[id]->flags & KCDB_CTI_FLAG_DELETED)) 
    {
        found = 1;
        if(type) {
            *type = &(kcdb_credtype_tbl[id]->ct);
            kcdb_credtype_hold(kcdb_credtype_tbl[id]);
        }
    } else {
        if(type)
            *type = NULL;
    }
    LeaveCriticalSection(&cs_credtype);

    if(found)
        return KHM_ERROR_SUCCESS;
    else
        return KHM_ERROR_NOT_FOUND;
}

KHMEXP khm_int32 KHMAPI kcdb_credtype_release_info(kcdb_credtype * type) 
{
    kcdb_credtype_i * ict;

    if(!type)
        return KHM_ERROR_INVALID_PARAM;

    ict = (kcdb_credtype_i *) type;
    return kcdb_credtype_release(ict);
}

KHMEXP khm_int32 KHMAPI kcdb_credtype_unregister(khm_int32 id) 
{
    kcdb_credtype_i * ict;

    if(id < 0 || id > KCDB_CREDTYPE_MAX_ID)
        return KHM_ERROR_INVALID_PARAM;

    EnterCriticalSection(&cs_credtype);
    ict = kcdb_credtype_tbl[id];
    ict->flags |= KCDB_CTI_FLAG_DELETED;
    kcdb_credtype_check_and_delete(id);
    LeaveCriticalSection(&cs_credtype);

    //kcdb_credtype_post_message(KCDB_OP_DELETE, &(ict->ct));
    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_handle KHMAPI kcdb_credtype_get_sub(khm_int32 id)
{
    kcdb_credtype_i * t;
    khm_handle s;

    if(id < 0 || id > KCDB_CREDTYPE_MAX_ID)
        return NULL;

    EnterCriticalSection(&cs_credtype);
    t = kcdb_credtype_tbl[id];
    if(t)
        s = t->ct.sub;
    else
        s = NULL;
    LeaveCriticalSection(&cs_credtype);

    return s;
}

KHMEXP khm_int32 KHMAPI kcdb_credtype_describe(
    khm_int32 id,
    wchar_t * buf,
    khm_size * cbbuf,
    khm_int32 flags)
{
    size_t s;
    size_t maxs;
    wchar_t * str;
    kcdb_credtype_i * t;
    khm_int32 rv = KHM_ERROR_SUCCESS;

    if(!cbbuf || id < 0 || id > KCDB_CREDTYPE_MAX_ID)
        return KHM_ERROR_INVALID_PARAM;

    EnterCriticalSection(&cs_credtype);
    t = kcdb_credtype_tbl[id];
    if(t) {
        if(flags & KCDB_TS_SHORT) {
            str = (t->ct.short_desc)?t->ct.short_desc:t->ct.name;
            maxs = (t->ct.short_desc)?KCDB_MAXCB_SHORT_DESC:KCDB_MAXCB_NAME;
        } else {
            str = (t->ct.long_desc)?t->ct.long_desc:((t->ct.short_desc)?t->ct.short_desc:t->ct.name);
            maxs = (t->ct.long_desc)?KCDB_MAXCB_LONG_DESC:((t->ct.short_desc)?KCDB_MAXCB_SHORT_DESC:KCDB_MAXCB_NAME);
        }
        StringCbLength(str, maxs, &s);
        s += sizeof(wchar_t);
        if(!buf || *cbbuf < s) {
            *cbbuf = s;
            rv = KHM_ERROR_TOO_LONG;
        } else {
            StringCbCopy(buf, *cbbuf, str);
            *cbbuf = s;
        }
    } else {
        if(buf && *cbbuf > 0)
            *buf = L'\0';
        *cbbuf = 0;
        rv = KHM_ERROR_NOT_FOUND;
    }
    LeaveCriticalSection(&cs_credtype);

    return rv;
}


KHMEXP khm_int32 KHMAPI kcdb_credtype_get_name(
    khm_int32 id,
    wchar_t * buf,
    khm_size * cbbuf)
{
    size_t s;
    kcdb_credtype_i * t;
    khm_int32 rv = KHM_ERROR_SUCCESS;

    if(!cbbuf || id < 0 || id > KCDB_CREDTYPE_MAX_ID)
        return KHM_ERROR_INVALID_PARAM;

    EnterCriticalSection(&cs_credtype);
    t = kcdb_credtype_tbl[id];
    if(t) {
        StringCbLength(t->ct.name, KCDB_MAXCB_NAME, &s);
        s += sizeof(wchar_t);
        if(!buf || *cbbuf < s) {
            *cbbuf = s;
            rv = KHM_ERROR_TOO_LONG;
        } else {
            StringCbCopy(buf, *cbbuf, t->ct.name);
            *cbbuf = s;
        }
    } else {
        *cbbuf = 0;
        rv = KHM_ERROR_NOT_FOUND;
    }
    LeaveCriticalSection(&cs_credtype);

    return rv;
}

KHMEXP khm_int32 KHMAPI kcdb_credtype_get_id(
    const wchar_t * name, 
    khm_int32 * id)
{
    int i;

    *id = 0;
    if(!name)
        return KHM_ERROR_INVALID_PARAM;

    EnterCriticalSection(&cs_credtype);
    for(i=0;i <= KCDB_CREDTYPE_MAX_ID; i++) {
        if(kcdb_credtype_tbl[i] && !wcscmp(name, kcdb_credtype_tbl[i]->ct.name))
            break;
    }
    LeaveCriticalSection(&cs_credtype);

    if(i <= KCDB_CREDTYPE_MAX_ID) {
        *id = i;
        return KHM_ERROR_SUCCESS;
    } else
        return KHM_ERROR_NOT_FOUND;
}

khm_int32 kcdb_credtype_get_next_free_id(khm_int32 * id) 
{
    int i;

    EnterCriticalSection(&cs_credtype);
    for(i=0;i <= KCDB_CREDTYPE_MAX_ID; i++) {
        if(!kcdb_credtype_tbl[i])
            break;
    }
    LeaveCriticalSection(&cs_credtype);

    if(i <= KCDB_CREDTYPE_MAX_ID) {
        *id = i;
        return KHM_ERROR_SUCCESS;
    } else {
        *id = -1;
        return KHM_ERROR_NO_RESOURCES;
    }
}

khm_int32 kcdb_credtype_hold(kcdb_credtype_i * ict) {
    
    if(!ict)
        return KHM_ERROR_INVALID_PARAM;

    EnterCriticalSection(&cs_credtype);
    ict->refcount++;
    LeaveCriticalSection(&cs_credtype);
    return KHM_ERROR_SUCCESS;
}

khm_int32 kcdb_credtype_release(kcdb_credtype_i * ict) {
    
    if(!ict)
        return KHM_ERROR_INVALID_PARAM;

    EnterCriticalSection(&cs_credtype);
    ict->refcount--;
    kcdb_credtype_check_and_delete(ict->ct.id);
    LeaveCriticalSection(&cs_credtype);
    return KHM_ERROR_SUCCESS;
}

void kcdb_credtype_msg_completion(kmq_message * m) 
{
    kcdb_credtype_release((kcdb_credtype_i *) m->vparam);
}

void kcdb_credtype_post_message(khm_int32 op, kcdb_credtype * type)
{
    kcdb_credtype_hold((kcdb_credtype_i *) type);
    kmq_post_message(KMSG_KCDB, KMSG_KCDB_CREDTYPE, op, (void *) type);
}
