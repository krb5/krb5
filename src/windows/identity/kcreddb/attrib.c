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

CRITICAL_SECTION cs_attrib;
hashtable * kcdb_attrib_namemap = NULL;
kcdb_attrib_i ** kcdb_attrib_tbl = NULL;
kcdb_attrib_i ** kcdb_property_tbl = NULL;
kcdb_attrib_i * kcdb_attribs = NULL;

void 
kcdb_attrib_add_ref_func(const void * key, void * va)
{
    kcdb_attrib_hold((kcdb_attrib_i *) va);
}

void 
kcdb_attrib_del_ref_func(const void * key, void * va)
{
    kcdb_attrib_release((kcdb_attrib_i *) va);
}

void 
kcdb_attrib_msg_completion(kmq_message * m) 
{
    if(m && m->vparam) {
        kcdb_attrib_release((kcdb_attrib_i *) m->vparam);
    }
}

khm_int32 
kcdb_attrib_hold(kcdb_attrib_i * ai)
{
    if(!ai)
        return KHM_ERROR_INVALID_PARAM;

    EnterCriticalSection(&cs_attrib);
    ai->refcount++;
    LeaveCriticalSection(&cs_attrib);
    return KHM_ERROR_SUCCESS;
}

khm_int32 
kcdb_attrib_release(kcdb_attrib_i * ai)
{
    if(!ai)
        return KHM_ERROR_INVALID_PARAM;

    EnterCriticalSection(&cs_attrib);
    ai->refcount--;
    LeaveCriticalSection(&cs_attrib);
    return KHM_ERROR_SUCCESS;
}

void 
kcdb_attrib_post_message(khm_int32 op, kcdb_attrib_i * ai)
{
    kcdb_attrib_hold(ai);
    kmq_post_message(KMSG_KCDB, KMSG_KCDB_ATTRIB, op, (void *) ai);
}

khm_int32 KHMAPI 
kcdb_attr_sys_cb(khm_handle vcred, 
                 khm_int32 attr, 
                 void * buf, 
                 khm_size * pcb_buf)
{
    kcdb_cred * c;

    c = (kcdb_cred *) vcred;

    switch(attr) {
    case KCDB_ATTR_NAME:
        return kcdb_cred_get_name(vcred, buf, pcb_buf);

    case KCDB_ATTR_ID:
        if(buf && *pcb_buf >= sizeof(khm_ui_8)) {
            *pcb_buf = sizeof(khm_int64);
            *((khm_ui_8 *) buf) = (khm_ui_8) c->identity;
            return KHM_ERROR_SUCCESS;
        } else {
            *pcb_buf = sizeof(khm_ui_8);
            return KHM_ERROR_TOO_LONG;
        }

    case KCDB_ATTR_ID_NAME:
        return kcdb_identity_get_name((khm_handle) c->identity, 
                                      (wchar_t *) buf, pcb_buf);

    case KCDB_ATTR_TYPE:
        if(buf && *pcb_buf >= sizeof(khm_int32)) {
            *pcb_buf = sizeof(khm_int32);
            *((khm_int32 *) buf) = c->type;
            return KHM_ERROR_SUCCESS;
        } else {
            *pcb_buf = sizeof(khm_int32);
            return KHM_ERROR_TOO_LONG;
        }

    case KCDB_ATTR_TYPE_NAME:
        return kcdb_credtype_describe(c->type, buf, 
                                      pcb_buf, KCDB_TS_SHORT);

    case KCDB_ATTR_TIMELEFT:
        {
            khm_int32 rv = KHM_ERROR_SUCCESS;

            if(!buf || *pcb_buf < sizeof(FILETIME)) {
                *pcb_buf = sizeof(FILETIME);
                rv = KHM_ERROR_TOO_LONG;
            } else if(!kcdb_cred_buf_exist(c,KCDB_ATTR_EXPIRE)) {
                *pcb_buf = sizeof(FILETIME);
                /* setting the timeleft to _I64_MAX has the
                   interpretation that this credential does not
                   expire, which is the default behavior if the
                   expiration time is not known */
                *((FILETIME *) buf) = IntToFt(_I64_MAX);
            } else {
                FILETIME ftc;
                khm_int64 iftc;

                GetSystemTimeAsFileTime(&ftc);
                iftc = FtToInt(&ftc);

                *((FILETIME *) buf) =
                    IntToFt(FtToInt((FILETIME *) 
                                    kcdb_cred_buf_get(c,KCDB_ATTR_EXPIRE))
                            - iftc);
                *pcb_buf = sizeof(FILETIME);
            }

            return rv;
        }

    case KCDB_ATTR_RENEW_TIMELEFT:
        {
            khm_int32 rv = KHM_ERROR_SUCCESS;

            if(!buf || *pcb_buf < sizeof(FILETIME)) {
                *pcb_buf = sizeof(FILETIME);
                rv = KHM_ERROR_TOO_LONG;
            } else if(!kcdb_cred_buf_exist(c,KCDB_ATTR_RENEW_EXPIRE)) {
                *pcb_buf = sizeof(FILETIME);
                /* setting the timeleft to _I64_MAX has the
                   interpretation that this credential does not
                   expire, which is the default behavior if the
                   expiration time is not known */
                *((FILETIME *) buf) = IntToFt(_I64_MAX);
            } else {
                FILETIME ftc;
                khm_int64 i_re;
                khm_int64 i_ct;

                GetSystemTimeAsFileTime(&ftc);

                i_re = FtToInt(((FILETIME *)
                                kcdb_cred_buf_get(c, KCDB_ATTR_RENEW_EXPIRE)));
                i_ct = FtToInt(&ftc);

                if (i_re > i_ct)
                    *((FILETIME *) buf) =
                        IntToFt(i_re - i_ct);
                else
                    *((FILETIME *) buf) =
                        IntToFt(0);

                *pcb_buf = sizeof(FILETIME);
            }

            return rv;
        }

    case KCDB_ATTR_FLAGS:
        if(buf && *pcb_buf >= sizeof(khm_int32)) {
            *pcb_buf = sizeof(khm_int32);
            *((khm_int32 *) buf) = c->flags;
            return KHM_ERROR_SUCCESS;
        } else {
            *pcb_buf = sizeof(khm_int32);
            return KHM_ERROR_TOO_LONG;
        }

    default:
        return KHM_ERROR_NOT_FOUND;
    }
}

void 
kcdb_attrib_init(void)
{
    kcdb_attrib attrib;
    wchar_t sbuf[256];

    InitializeCriticalSection(&cs_attrib);
    kcdb_attrib_namemap = 
        hash_new_hashtable(KCDB_ATTRIB_HASH_SIZE,
                           hash_string,
                           hash_string_comp,
                           kcdb_attrib_add_ref_func,
                           kcdb_attrib_del_ref_func);

    kcdb_attrib_tbl = 
        PMALLOC(sizeof(kcdb_attrib_i *) * (KCDB_ATTR_MAX_ID + 1));
    assert(kcdb_attrib_tbl != NULL);
    ZeroMemory(kcdb_attrib_tbl, 
               sizeof(kcdb_attrib_i *) * (KCDB_ATTR_MAX_ID + 1));

    kcdb_property_tbl = 
        PMALLOC(sizeof(kcdb_attrib_i *) * KCDB_ATTR_MAX_PROPS);
    assert(kcdb_property_tbl != NULL);
    ZeroMemory(kcdb_property_tbl, 
               sizeof(kcdb_attrib_i *) * KCDB_ATTR_MAX_PROPS);

    kcdb_attribs = NULL;

    /* register standard attributes */
    
    /* Name */
    attrib.id = KCDB_ATTR_NAME;
    attrib.name = KCDB_ATTRNAME_NAME;
    attrib.type = KCDB_TYPE_STRING;
    LoadString(hinst_kcreddb, IDS_NAME, sbuf, ARRAYLENGTH(sbuf));
    attrib.short_desc = sbuf;
    attrib.long_desc = NULL;
    attrib.flags = 
        KCDB_ATTR_FLAG_REQUIRED | 
        KCDB_ATTR_FLAG_COMPUTED | 
        KCDB_ATTR_FLAG_SYSTEM;
    attrib.compute_cb = kcdb_attr_sys_cb;
    attrib.compute_min_cbsize = sizeof(wchar_t);
    attrib.compute_max_cbsize = KCDB_MAXCB_NAME;

    kcdb_attrib_register(&attrib, NULL);

    /* ID */
    attrib.id = KCDB_ATTR_ID;
    attrib.name = KCDB_ATTRNAME_ID;
    attrib.type = KCDB_TYPE_INT64;
    LoadString(hinst_kcreddb, IDS_IDENTITY, sbuf, ARRAYLENGTH(sbuf));
    attrib.short_desc = sbuf;
    attrib.long_desc = NULL;
    attrib.flags = 
        KCDB_ATTR_FLAG_REQUIRED | 
        KCDB_ATTR_FLAG_COMPUTED | 
        KCDB_ATTR_FLAG_SYSTEM |
        KCDB_ATTR_FLAG_HIDDEN;
    attrib.compute_cb = kcdb_attr_sys_cb;
    attrib.compute_min_cbsize = sizeof(khm_int32);
    attrib.compute_max_cbsize = sizeof(khm_int32);

    kcdb_attrib_register(&attrib, NULL);

    /* ID Name */
    attrib.id = KCDB_ATTR_ID_NAME;
    attrib.alt_id = KCDB_ATTR_ID;
    attrib.name = KCDB_ATTRNAME_ID_NAME;
    attrib.type = KCDB_TYPE_STRING;
    LoadString(hinst_kcreddb, IDS_IDENTITY, sbuf, ARRAYLENGTH(sbuf));
    attrib.short_desc = sbuf;
    attrib.long_desc = NULL;
    attrib.flags = 
        KCDB_ATTR_FLAG_REQUIRED | 
        KCDB_ATTR_FLAG_COMPUTED | 
        KCDB_ATTR_FLAG_ALTVIEW |
        KCDB_ATTR_FLAG_SYSTEM;
    attrib.compute_cb = kcdb_attr_sys_cb;
    attrib.compute_min_cbsize = sizeof(wchar_t);
    attrib.compute_max_cbsize = KCDB_IDENT_MAXCB_NAME;

    kcdb_attrib_register(&attrib, NULL);

    /* Type */
    attrib.id = KCDB_ATTR_TYPE;
    attrib.name = KCDB_ATTRNAME_TYPE;
    attrib.type = KCDB_TYPE_INT32;
    LoadString(hinst_kcreddb, IDS_TYPE, sbuf, ARRAYLENGTH(sbuf));
    attrib.short_desc = sbuf;
    attrib.long_desc = NULL;
    attrib.flags = 
        KCDB_ATTR_FLAG_REQUIRED | 
        KCDB_ATTR_FLAG_COMPUTED | 
        KCDB_ATTR_FLAG_SYSTEM |
        KCDB_ATTR_FLAG_HIDDEN;
    attrib.compute_cb = kcdb_attr_sys_cb;
    attrib.compute_min_cbsize = sizeof(khm_int32);
    attrib.compute_max_cbsize = sizeof(khm_int32);

    kcdb_attrib_register(&attrib, NULL);

    /* Type Name */
    attrib.id = KCDB_ATTR_TYPE_NAME;
    attrib.alt_id = KCDB_ATTR_TYPE;
    attrib.name = KCDB_ATTRNAME_TYPE_NAME;
    attrib.type = KCDB_TYPE_STRING;
    LoadString(hinst_kcreddb, IDS_TYPE, sbuf, ARRAYLENGTH(sbuf));
    attrib.short_desc = sbuf;
    attrib.long_desc = NULL;
    attrib.flags = 
        KCDB_ATTR_FLAG_REQUIRED | 
        KCDB_ATTR_FLAG_COMPUTED |
        KCDB_ATTR_FLAG_ALTVIEW |
        KCDB_ATTR_FLAG_SYSTEM;
    attrib.compute_cb = kcdb_attr_sys_cb;
    attrib.compute_min_cbsize = sizeof(wchar_t);
    attrib.compute_max_cbsize = KCDB_MAXCB_NAME;

    kcdb_attrib_register(&attrib, NULL);

    /* Parent Name */
    attrib.id = KCDB_ATTR_PARENT_NAME;
    attrib.name = KCDB_ATTRNAME_PARENT_NAME;
    attrib.type = KCDB_TYPE_STRING;
    LoadString(hinst_kcreddb, IDS_PARENT, sbuf, ARRAYLENGTH(sbuf));
    attrib.short_desc = sbuf;
    attrib.long_desc = NULL;
    attrib.flags = KCDB_ATTR_FLAG_SYSTEM | KCDB_ATTR_FLAG_HIDDEN;
    attrib.compute_cb = NULL;
    attrib.compute_min_cbsize = 0;
    attrib.compute_max_cbsize = 0;

    kcdb_attrib_register(&attrib, NULL);

    /* Issed On */
    attrib.id = KCDB_ATTR_ISSUE;
    attrib.name = KCDB_ATTRNAME_ISSUE;
    attrib.type = KCDB_TYPE_DATE;
    LoadString(hinst_kcreddb, IDS_ISSUED, sbuf, ARRAYLENGTH(sbuf));
    attrib.short_desc = sbuf;
    attrib.long_desc = NULL;
    attrib.flags = KCDB_ATTR_FLAG_SYSTEM;
    attrib.compute_cb = NULL;
    attrib.compute_min_cbsize = 0;
    attrib.compute_max_cbsize = 0;

    kcdb_attrib_register(&attrib, NULL);

    /* Expires On */
    attrib.id = KCDB_ATTR_EXPIRE;
    attrib.name = KCDB_ATTRNAME_EXPIRE;
    attrib.type = KCDB_TYPE_DATE;
    LoadString(hinst_kcreddb, IDS_EXPIRES, sbuf, ARRAYLENGTH(sbuf));
    attrib.short_desc = sbuf;
    attrib.long_desc = NULL;
    attrib.flags = KCDB_ATTR_FLAG_SYSTEM;
    attrib.compute_cb = NULL;
    attrib.compute_min_cbsize = 0;
    attrib.compute_max_cbsize = 0;

    kcdb_attrib_register(&attrib, NULL);

    /* Renewable Time Expires On */
    attrib.id = KCDB_ATTR_RENEW_EXPIRE;
    attrib.name = KCDB_ATTRNAME_RENEW_EXPIRE;
    attrib.type = KCDB_TYPE_DATE;
    LoadString(hinst_kcreddb, IDS_RENEW_EXPIRES, 
               sbuf, ARRAYLENGTH(sbuf));
    attrib.short_desc = sbuf;
    attrib.long_desc = NULL;
    attrib.flags = KCDB_ATTR_FLAG_SYSTEM;
    attrib.compute_cb = NULL;
    attrib.compute_min_cbsize = 0;
    attrib.compute_max_cbsize = 0;

    kcdb_attrib_register(&attrib, NULL);

    /* Time Left */
    attrib.id = KCDB_ATTR_TIMELEFT;
    attrib.alt_id = KCDB_ATTR_EXPIRE;
    attrib.name = KCDB_ATTRNAME_TIMELEFT;
    attrib.type = KCDB_TYPE_INTERVAL;
    LoadString(hinst_kcreddb, IDS_TIMELEFT, sbuf, ARRAYLENGTH(sbuf));
    attrib.short_desc = sbuf;
    attrib.long_desc = NULL;
    attrib.flags = KCDB_ATTR_FLAG_SYSTEM |
        KCDB_ATTR_FLAG_COMPUTED |
        KCDB_ATTR_FLAG_ALTVIEW |
        KCDB_ATTR_FLAG_VOLATILE;
    attrib.compute_cb = kcdb_attr_sys_cb;
    attrib.compute_min_cbsize = sizeof(FILETIME);
    attrib.compute_max_cbsize = sizeof(FILETIME);

    kcdb_attrib_register(&attrib, NULL);

    /* Renewable Time Left */
    attrib.id = KCDB_ATTR_RENEW_TIMELEFT;
    attrib.alt_id = KCDB_ATTR_RENEW_EXPIRE;
    attrib.name = KCDB_ATTRNAME_RENEW_TIMELEFT;
    attrib.type = KCDB_TYPE_INTERVAL;
    LoadString(hinst_kcreddb, 
               IDS_RENEW_TIMELEFT, sbuf, ARRAYLENGTH(sbuf));
    attrib.short_desc = sbuf;
    attrib.long_desc = NULL;
    attrib.flags = KCDB_ATTR_FLAG_SYSTEM |
        KCDB_ATTR_FLAG_COMPUTED |
        KCDB_ATTR_FLAG_ALTVIEW |
        KCDB_ATTR_FLAG_VOLATILE;
    attrib.compute_cb = kcdb_attr_sys_cb;
    attrib.compute_min_cbsize = sizeof(FILETIME);
    attrib.compute_max_cbsize = sizeof(FILETIME);

    kcdb_attrib_register(&attrib, NULL);

    /* Location of Credential */
    attrib.id = KCDB_ATTR_LOCATION;
    attrib.name = KCDB_ATTRNAME_LOCATION;
    attrib.type = KCDB_TYPE_STRING;
    LoadString(hinst_kcreddb, IDS_LOCATION, sbuf, ARRAYLENGTH(sbuf));
    attrib.short_desc = sbuf;
    attrib.long_desc = NULL;
    attrib.flags = KCDB_ATTR_FLAG_SYSTEM;
    attrib.compute_cb = NULL;
    attrib.compute_min_cbsize = 0;
    attrib.compute_max_cbsize = 0;

    kcdb_attrib_register(&attrib, NULL);

    /* Lifetime */
    attrib.id = KCDB_ATTR_LIFETIME;
    attrib.name = KCDB_ATTRNAME_LIFETIME;
    attrib.type = KCDB_TYPE_INTERVAL;
    LoadString(hinst_kcreddb, IDS_LIFETIME, sbuf, ARRAYLENGTH(sbuf));
    attrib.short_desc = sbuf;
    attrib.long_desc = NULL;
    attrib.flags = KCDB_ATTR_FLAG_SYSTEM;
    attrib.compute_cb = NULL;
    attrib.compute_min_cbsize = 0;
    attrib.compute_max_cbsize = 0;

    kcdb_attrib_register(&attrib, NULL);

    /* Renewable Lifetime */
    attrib.id = KCDB_ATTR_RENEW_LIFETIME;
    attrib.name = KCDB_ATTRNAME_RENEW_LIFETIME;
    attrib.type = KCDB_TYPE_INTERVAL;
    LoadString(hinst_kcreddb, 
               IDS_RENEW_LIFETIME, sbuf, ARRAYLENGTH(sbuf));
    attrib.short_desc = sbuf;
    attrib.long_desc = NULL;
    attrib.flags = KCDB_ATTR_FLAG_SYSTEM;
    attrib.compute_cb = NULL;
    attrib.compute_min_cbsize = 0;
    attrib.compute_max_cbsize = 0;

    kcdb_attrib_register(&attrib, NULL);

    /* Flags */
    attrib.id = KCDB_ATTR_FLAGS;
    attrib.name = KCDB_ATTRNAME_FLAGS;
    attrib.type = KCDB_TYPE_INT32;
    LoadString(hinst_kcreddb, IDS_FLAGS, sbuf, ARRAYLENGTH(sbuf));
    attrib.short_desc = sbuf;
    attrib.long_desc = NULL;
    attrib.flags = 
        KCDB_ATTR_FLAG_REQUIRED | 
        KCDB_ATTR_FLAG_COMPUTED | 
        KCDB_ATTR_FLAG_SYSTEM |
        KCDB_ATTR_FLAG_HIDDEN;
    attrib.compute_cb = kcdb_attr_sys_cb;
    attrib.compute_min_cbsize = sizeof(khm_int32);
    attrib.compute_max_cbsize = sizeof(khm_int32);

    kcdb_attrib_register(&attrib, NULL);
}

void 
kcdb_attrib_exit(void)
{
    DeleteCriticalSection(&cs_attrib);
    
    if(kcdb_attrib_tbl)
        PFREE(kcdb_attrib_tbl);

    if(kcdb_property_tbl)
        PFREE(kcdb_property_tbl);
}

KHMEXP khm_int32 KHMAPI 
kcdb_attrib_get_id(const wchar_t *name, khm_int32 * id)
{
    kcdb_attrib_i * ai;

    if(!name)
        return KHM_ERROR_INVALID_PARAM;

    EnterCriticalSection(&cs_attrib);
    ai = hash_lookup(kcdb_attrib_namemap, (void *) name);
    LeaveCriticalSection(&cs_attrib);

    if(ai) {
        *id = ai->attr.id;
        return KHM_ERROR_SUCCESS;
    } else {
        *id = KCDB_ATTR_INVALID;
        return KHM_ERROR_NOT_FOUND;
    }
}

KHMEXP khm_int32 KHMAPI 
kcdb_attrib_register(const kcdb_attrib * attrib, khm_int32 * new_id)
{
    kcdb_attrib_i * ai;
    size_t cb_name;
    size_t cb_short_desc;
    size_t cb_long_desc;
    khm_int32 attr_id;
    khm_boolean prop = FALSE;

    if(!attrib ||
        KHM_FAILED(kcdb_type_get_info(attrib->type, NULL)) ||
        !attrib->name)
        return KHM_ERROR_INVALID_PARAM;

    if(FAILED(StringCbLength(attrib->name, KCDB_MAXCB_NAME, &cb_name)))
        return KHM_ERROR_TOO_LONG;
    cb_name += sizeof(wchar_t);

    if(attrib->short_desc) {
        if(FAILED(StringCbLength(attrib->short_desc, KCDB_MAXCB_SHORT_DESC, &cb_short_desc)))
            return KHM_ERROR_TOO_LONG;
        cb_short_desc += sizeof(wchar_t);
    } else
        cb_short_desc = 0;

    if(attrib->long_desc) {
        if(FAILED(StringCbLength(attrib->long_desc, KCDB_MAXCB_LONG_DESC, &cb_long_desc)))
            return KHM_ERROR_TOO_LONG;
        cb_long_desc += sizeof(wchar_t);
    } else
        cb_long_desc = 0;

    if((attrib->flags & KCDB_ATTR_FLAG_COMPUTED) && 
        (!attrib->compute_cb ||
        attrib->compute_min_cbsize <= 0 ||
        attrib->compute_max_cbsize < attrib->compute_min_cbsize))
        return KHM_ERROR_INVALID_PARAM;

    if ((attrib->flags & KCDB_ATTR_FLAG_ALTVIEW) &&
        KHM_FAILED(kcdb_attrib_get_info(attrib->alt_id,
                                        NULL)))
        return KHM_ERROR_INVALID_PARAM;

    prop = !!(attrib->flags & KCDB_ATTR_FLAG_PROPERTY);

    EnterCriticalSection(&cs_attrib);

    if(!prop && 
       (attrib->id < 0 || attrib->id > KCDB_ATTR_MAX_ID)) 
    {
        if(KHM_FAILED(kcdb_attrib_next_free_id(&attr_id))) {
            LeaveCriticalSection(&cs_attrib);
            return KHM_ERROR_NO_RESOURCES;
        }
    } else if (prop &&
               (attrib->id < KCDB_ATTR_MIN_PROP_ID || 
                attrib->id > KCDB_ATTR_MAX_PROP_ID)) {

        if(KHM_FAILED(kcdb_attrib_next_free_prop_id(&attr_id))) {
            LeaveCriticalSection(&cs_attrib);
            return KHM_ERROR_NO_RESOURCES;
        }

    } else {
        attr_id = attrib->id;
    }

#ifdef DEBUG
    assert(!prop || (attr_id >= KCDB_ATTR_MIN_PROP_ID && attr_id <= KCDB_ATTR_MAX_PROP_ID));
    assert(prop  || (attr_id >= 0 && attr_id <= KCDB_ATTR_MAX_ID));
#endif

    if((!prop && kcdb_attrib_tbl[attr_id]) ||
       (prop && kcdb_property_tbl[attr_id - KCDB_ATTR_MIN_PROP_ID])) {

        LeaveCriticalSection(&cs_attrib);
        return KHM_ERROR_DUPLICATE;

    }

    ai = PMALLOC(sizeof(kcdb_attrib_i));
    ZeroMemory(ai, sizeof(kcdb_attrib_i));

    ai->attr.type = attrib->type;
    ai->attr.id = attr_id;
    ai->attr.alt_id = attrib->alt_id;
    ai->attr.flags = attrib->flags;
    ai->attr.compute_cb = attrib->compute_cb;
    ai->attr.compute_max_cbsize = attrib->compute_max_cbsize;
    ai->attr.compute_min_cbsize = attrib->compute_min_cbsize;
    ai->attr.name = PMALLOC(cb_name);
    StringCbCopy(ai->attr.name, cb_name, attrib->name);
    if(cb_short_desc) {
        ai->attr.short_desc = PMALLOC(cb_short_desc);
        StringCbCopy(ai->attr.short_desc, cb_short_desc, attrib->short_desc);
    }
    if(cb_long_desc) {
        ai->attr.long_desc = PMALLOC(cb_long_desc);
        StringCbCopy(ai->attr.long_desc, cb_long_desc, attrib->long_desc);
    }

    LINIT(ai);

    if(!prop)
        kcdb_attrib_tbl[attr_id] = ai;
    else
        kcdb_property_tbl[attr_id - KCDB_ATTR_MIN_PROP_ID] = ai;

    LPUSH(&kcdb_attribs, ai);

    hash_add(kcdb_attrib_namemap, (void *) ai->attr.name, ai);

    LeaveCriticalSection(&cs_attrib);

    kcdb_attrib_post_message(KCDB_OP_INSERT, ai);

    if(new_id)
        *new_id = attr_id;

    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32 KHMAPI kcdb_attrib_get_info(
    khm_int32 id, 
    kcdb_attrib ** attrib)
{
    kcdb_attrib_i * ai;
    khm_boolean prop;

    if(id >= 0 && id <= KCDB_ATTR_MAX_ID)
        prop = FALSE;
    else if(id >= KCDB_ATTR_MIN_PROP_ID && id <= KCDB_ATTR_MAX_PROP_ID)
        prop = TRUE;
    else
        return KHM_ERROR_INVALID_PARAM;

    EnterCriticalSection(&cs_attrib);
    if(prop)
        ai = kcdb_property_tbl[id - KCDB_ATTR_MIN_PROP_ID];
    else
        ai = kcdb_attrib_tbl[id];
    LeaveCriticalSection(&cs_attrib);

    if(ai) {
        if(attrib) {
            *attrib = &(ai->attr);
            kcdb_attrib_hold(ai);
        }
        return KHM_ERROR_SUCCESS;
    } else {
        if(attrib)
            *attrib = NULL;
        return KHM_ERROR_NOT_FOUND;
    }
}

KHMEXP khm_int32 KHMAPI kcdb_attrib_release_info(kcdb_attrib * attrib)
{
    if(attrib)
        kcdb_attrib_release((kcdb_attrib_i *) attrib);
    return KHM_ERROR_SUCCESS;
}


KHMEXP khm_int32 KHMAPI kcdb_attrib_unregister(khm_int32 id)
{
    /*TODO: implement this */
    return KHM_ERROR_NOT_IMPLEMENTED;
}

KHMEXP khm_int32 KHMAPI kcdb_attrib_describe(
    khm_int32 id, 
    wchar_t * buffer, 
    khm_size * cbsize, 
    khm_int32 flags)
{
    kcdb_attrib_i * ai;
    size_t cb_size = 0;
    khm_boolean prop = FALSE;

    if(!cbsize)
        return KHM_ERROR_INVALID_PARAM;

    if(id >= 0 && id <= KCDB_ATTR_MAX_ID)
        prop = FALSE;
    else if(id >= KCDB_ATTR_MIN_PROP_ID && id <= KCDB_ATTR_MAX_PROP_ID)
        prop = TRUE;
    else 
	return KHM_ERROR_INVALID_PARAM;

    if(prop)
        ai = kcdb_property_tbl[id - KCDB_ATTR_MIN_PROP_ID];
    else
        ai = kcdb_attrib_tbl[id];

    if(!ai)
        return KHM_ERROR_NOT_FOUND;

    if((flags & KCDB_TS_SHORT) &&
        ai->attr.short_desc) 
    {
        if(FAILED(StringCbLength(ai->attr.short_desc, KCDB_MAXCB_SHORT_DESC, &cb_size)))
            return KHM_ERROR_UNKNOWN;
        cb_size += sizeof(wchar_t);

        if(!buffer || *cbsize < cb_size) {
            *cbsize = cb_size;
            return KHM_ERROR_TOO_LONG;
        }

        StringCbCopy(buffer, *cbsize, ai->attr.short_desc);

        *cbsize = cb_size;

        return KHM_ERROR_SUCCESS;
    } else {
        if(FAILED(StringCbLength(ai->attr.long_desc, KCDB_MAXCB_LONG_DESC, &cb_size)))
            return KHM_ERROR_UNKNOWN;
        cb_size += sizeof(wchar_t);

        if(!buffer || *cbsize < cb_size) {
            *cbsize = cb_size;
            return KHM_ERROR_TOO_LONG;
        }

        StringCbCopy(buffer, *cbsize, ai->attr.long_desc);

        *cbsize = cb_size;

        return KHM_ERROR_SUCCESS;
    }
}

khm_int32 kcdb_attrib_next_free_prop_id(khm_int32 * id)
{
    int i;

    if(!id)
        return KHM_ERROR_INVALID_PARAM;

    EnterCriticalSection(&cs_attrib);
    for(i=0;i < KCDB_ATTR_MAX_PROPS; i++) {
        if(!kcdb_property_tbl[i])
            break;
    }
    LeaveCriticalSection(&cs_attrib);

    if(i < KCDB_ATTR_MAX_PROPS) {
        *id = i + KCDB_ATTR_MIN_PROP_ID;
        return KHM_ERROR_SUCCESS;
    } else {
        *id = KCDB_ATTR_INVALID;
        return KHM_ERROR_NO_RESOURCES;
    }
}

khm_int32 kcdb_attrib_next_free_id(khm_int32 * id)
{
    int i;

    if(!id)
        return KHM_ERROR_INVALID_PARAM;

    EnterCriticalSection(&cs_attrib);
    for(i=0;i<= KCDB_ATTR_MAX_ID; i++) {
        if(!kcdb_attrib_tbl[i])
            break;
    }
    LeaveCriticalSection(&cs_attrib);

    if(i <= KCDB_ATTR_MAX_ID) {
        *id = i;
        return KHM_ERROR_SUCCESS;
    } else {
        *id = KCDB_ATTR_INVALID;
        return KHM_ERROR_NO_RESOURCES;
    }
}

KHMEXP khm_int32 KHMAPI kcdb_attrib_get_count(
    khm_int32 and_flags,
    khm_int32 eq_flags,
    khm_size * pcount)
{
    khm_int32 rv = KHM_ERROR_SUCCESS;
    khm_size count = 0;
    int i;

    if(pcount == NULL)
        return KHM_ERROR_INVALID_PARAM;

    eq_flags &= and_flags;

    EnterCriticalSection(&cs_attrib);
    for(i = 0; i <= KCDB_ATTR_MAX_ID; i++) {
        if(kcdb_attrib_tbl[i] &&
            (kcdb_attrib_tbl[i]->attr.flags & and_flags) == eq_flags)
            count++;
    }

    for(i = 0; i < KCDB_ATTR_MAX_PROPS; i++) {
        if(kcdb_property_tbl[i] &&
            (kcdb_property_tbl[i]->attr.flags & and_flags) == eq_flags)
            count++;
    }
    LeaveCriticalSection(&cs_attrib);

    *pcount = count;

    return rv;
}

KHMEXP khm_int32 KHMAPI kcdb_attrib_get_ids(
    khm_int32 and_flags,
    khm_int32 eq_flags,
    khm_int32 * plist,
    khm_size * pcsize)
{
    khm_int32 rv = KHM_ERROR_SUCCESS;
    khm_size count = 0;
    int i;

    if(plist == NULL || pcsize == NULL)
        return KHM_ERROR_INVALID_PARAM;

    eq_flags &= and_flags;

    EnterCriticalSection(&cs_attrib);
    for(i = 0; i <= KCDB_ATTR_MAX_ID; i++) {
        if(kcdb_attrib_tbl[i] &&
            (kcdb_attrib_tbl[i]->attr.flags & and_flags) == eq_flags) {
            if(count >= *pcsize) {
                rv = KHM_ERROR_TOO_LONG;
                count++;
            } else
                plist[count++] = i;
        }
    }

    for(i = 0; i < KCDB_ATTR_MAX_PROPS; i++) {
        if(kcdb_property_tbl[i] &&
            (kcdb_property_tbl[i]->attr.flags & and_flags) == eq_flags) {
            if(count >= *pcsize) {
                rv = KHM_ERROR_TOO_LONG;
                count++;
            } else
                plist[count++] = i + KCDB_ATTR_MIN_PROP_ID;
        }
    }
    LeaveCriticalSection(&cs_attrib);

    *pcsize = count;

    return rv;
}
