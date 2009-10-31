/*
 * Copyright (c) 2005 Massachusetts Institute of Technology
 * Copyright (c) 2007 Secure Endpoints Inc.
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

static CRITICAL_SECTION cs_ident;
hashtable * kcdb_identities_namemap = NULL;
khm_int32 kcdb_n_identities = 0;
kcdb_identity * kcdb_identities = NULL;
kcdb_identity * kcdb_def_identity = NULL;
khm_handle kcdb_ident_sub = NULL; /* identity provider */
khm_int32  kcdb_ident_cred_type = KCDB_CREDTYPE_INVALID;
/* primary credentials type */
khm_ui_4 kcdb_ident_refresh_cycle = 0;
khm_boolean kcdb_checked_config = FALSE;
khm_boolean kcdb_checking_config = FALSE;

KHMEXP khm_boolean KHMAPI
kcdb_identity_is_equal(khm_handle identity1,
                       khm_handle identity2)
{

    return (identity1 == identity2);

}

KHMEXP khm_int32 KHMAPI
kcdb_identity_set_provider(khm_handle sub)
{
    EnterCriticalSection(&cs_ident);
    if (sub != kcdb_ident_sub) {
        if(kcdb_ident_sub != NULL) {
            kmq_send_sub_msg(kcdb_ident_sub,
                             KMSG_IDENT,
                             KMSG_IDENT_EXIT,
                             0,
                             0);
            kmq_delete_subscription(kcdb_ident_sub);
        }
        kcdb_ident_sub = sub;

        if (kcdb_ident_sub)
            kmq_send_sub_msg(kcdb_ident_sub,
                             KMSG_IDENT,
                             KMSG_IDENT_INIT,
                             0,
                             0);
    }
    LeaveCriticalSection(&cs_ident);
    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32 KHMAPI
kcdb_identity_get_provider(khm_handle * sub)
{
    khm_int32 rv = KHM_ERROR_SUCCESS;

    EnterCriticalSection(&cs_ident);
    if(kcdb_ident_sub != NULL)
        rv = KHM_ERROR_SUCCESS;
    else
        rv = KHM_ERROR_NOT_FOUND;
    if(sub != NULL)
        *sub = kcdb_ident_sub;
    LeaveCriticalSection(&cs_ident);

    return rv;
}

KHMEXP khm_int32 KHMAPI
kcdb_identity_set_type(khm_int32 cred_type)
{
    EnterCriticalSection(&cs_ident);
    kcdb_ident_cred_type = cred_type;
    LeaveCriticalSection(&cs_ident);

    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32 KHMAPI
kcdb_identity_get_type(khm_int32 * ptype)
{
    if (!ptype)
        return KHM_ERROR_INVALID_PARAM;

    EnterCriticalSection(&cs_ident);
    *ptype = kcdb_ident_cred_type;
    LeaveCriticalSection(&cs_ident);

    if (*ptype >= 0)
        return KHM_ERROR_SUCCESS;
    else
        return KHM_ERROR_NOT_FOUND;
}

/* message completion routine */
void
kcdbint_ident_msg_completion(kmq_message * m) {
    kcdb_identity_release(m->vparam);
}

void
kcdbint_ident_add_ref(const void * key, void * vid) {
    /* References in the hashtable are not refcounted */

    // kcdb_identity_hold(vid);
}

void
kcdbint_ident_del_ref(const void * key, void * vid) {
    /* References in the hashtable are not refcounted */

    // kcdb_identity_release(vid);
}

void
kcdbint_ident_init(void) {
    InitializeCriticalSection(&cs_ident);
    kcdb_identities_namemap = hash_new_hashtable(
        KCDB_IDENT_HASHTABLE_SIZE,
        hash_string,
        hash_string_comp,
        kcdbint_ident_add_ref,
        kcdbint_ident_del_ref);
}

void
kcdbint_ident_exit(void) {
    EnterCriticalSection(&cs_ident);
    hash_del_hashtable(kcdb_identities_namemap);
    LeaveCriticalSection(&cs_ident);
    DeleteCriticalSection(&cs_ident);
}

/* NOT called with cs_ident held */
KHMEXP khm_boolean KHMAPI
kcdb_identity_is_valid_name(const wchar_t * name)
{
    khm_int32 rv;

    /* special case.  Note since the string we are comparing with is
       of a known length we don't need to check the length of name. */
    if (!wcscmp(name, L"_Schema"))
        return FALSE;

    rv = kcdb_identpro_validate_name(name);

    if(rv == KHM_ERROR_NO_PROVIDER ||
       rv == KHM_ERROR_NOT_IMPLEMENTED)
        return TRUE;
    else
        return KHM_SUCCEEDED(rv);
}

KHMEXP khm_int32 KHMAPI
kcdb_identity_create(const wchar_t *name,
                     khm_int32 flags,
                     khm_handle * result) {
    kcdb_identity * id = NULL;
    kcdb_identity * id_tmp = NULL;
    size_t namesize;

    if(!result || !name)
        return KHM_ERROR_INVALID_PARAM;

    *result = NULL;

    /* is it there already? */
    EnterCriticalSection(&cs_ident);
    id = hash_lookup(kcdb_identities_namemap, (void *) name);
    if(id)
        kcdb_identity_hold((khm_handle) id);
    LeaveCriticalSection(&cs_ident);

    if(id) {
        *result = (khm_handle) id;
        return KHM_ERROR_SUCCESS;
    } else if(!(flags & KCDB_IDENT_FLAG_CREATE)) {
        return KHM_ERROR_NOT_FOUND;
    }

    flags &= ~KCDB_IDENT_FLAG_CREATE;

    /* nope. create it */
    if((flags & ~KCDB_IDENT_FLAGMASK_RDWR) ||
       (flags & (KCDB_IDENT_FLAG_DEFAULT |
                 KCDB_IDENT_FLAG_SEARCHABLE |
                 KCDB_IDENT_FLAG_STICKY))) {
        /* can't specify this flag in create */
        return KHM_ERROR_INVALID_PARAM;
    }

    if(!kcdb_identity_is_valid_name(name)) {
        return KHM_ERROR_INVALID_NAME;
    }

    /* we expect the following will succeed since the above
       test passed */
    StringCbLength(name, KCDB_IDENT_MAXCB_NAME, &namesize);
    namesize += sizeof(wchar_t);

    id = PMALLOC(sizeof(kcdb_identity));
    ZeroMemory(id, sizeof(kcdb_identity));
    id->magic = KCDB_IDENT_MAGIC;
    id->name = PMALLOC(namesize);
    StringCbCopy(id->name, namesize, name);

    id->flags = (flags & KCDB_IDENT_FLAGMASK_RDWR);
    id->flags |= KCDB_IDENT_FLAG_ACTIVE | KCDB_IDENT_FLAG_EMPTY;
    LINIT(id);

    EnterCriticalSection(&cs_ident);
    id_tmp = hash_lookup(kcdb_identities_namemap, (void *) id->name);
    if(id_tmp) {
        /* lost a race */
        kcdb_identity_hold((khm_handle) id_tmp);
        *result = (khm_handle) id_tmp;

        PFREE(id->name);
        PFREE(id);

        id = NULL;
    } else {
        khm_handle h_cfg;

        kcdb_identity_hold((khm_handle) id);
        hash_add(kcdb_identities_namemap,
                 (void *) id->name,
                 (void *) id);
        LPUSH(&kcdb_identities, id);

        if(KHM_SUCCEEDED(kcdb_identity_get_config((khm_handle) id,
                                                  0,
                                                  &h_cfg))) {
            /* don't need to set the KCDB_IDENT_FLAG_CONFIG flags
               since kcdb_identity_get_config() sets it for us. */
            khm_int32 sticky;

            if (KHM_SUCCEEDED(khc_read_int32(h_cfg, L"Sticky", &sticky)) &&
                sticky) {
                id->flags |= KCDB_IDENT_FLAG_STICKY;
            }

            khc_close_space(h_cfg);
        }
    }
    LeaveCriticalSection(&cs_ident);

    if(id != NULL) {
        *result = (khm_handle) id;

        kcdb_identpro_notify_create((khm_handle) id);

        kcdbint_ident_post_message(KCDB_OP_INSERT, id);
    }

    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32 KHMAPI
kcdb_identity_delete(khm_handle vid) {
    kcdb_identity * id;
    khm_int32 code = KHM_ERROR_SUCCESS;

    EnterCriticalSection(&cs_ident);
    if(!kcdb_is_identity(vid)) {
        code = KHM_ERROR_INVALID_PARAM;
        goto _exit;
    }

    id = (kcdb_identity *) vid;

    if (kcdb_is_active_identity(vid)) {

        id->flags &= ~KCDB_IDENT_FLAG_ACTIVE;

        hash_del(kcdb_identities_namemap, (void *) id->name);

        LeaveCriticalSection(&cs_ident);

        kcdbint_ident_post_message(KCDB_OP_DELETE, id);

        /* Once everybody finishes dealing with the identity deletion,
           we will get called again. */
        return KHM_ERROR_SUCCESS;
    } else if (id->refcount == 0) {
        /* If the identity is not active, it is not in the hashtable
           either */
        LDELETE(&kcdb_identities, id);

        if (id->name)
            PFREE(id->name);
        PFREE(id);
    }
    /* else, we have an identity that is not active, but has
       outstanding references.  We have to wait until those references
       are freed.  Once they are released, kcdb_identity_delete() will
       be called again. */

 _exit:
    LeaveCriticalSection(&cs_ident);

    return code;
}

KHMEXP khm_int32 KHMAPI
kcdb_identity_set_flags(khm_handle vid,
                        khm_int32 flag,
                        khm_int32 mask) {
    kcdb_identity * id;
    khm_int32 oldflags;
    khm_int32 newflags;
    khm_int32 delta = 0;
    khm_int32 rv;

    if (mask == 0)
        return KHM_ERROR_SUCCESS;

    if(!kcdb_is_active_identity(vid))
        return KHM_ERROR_INVALID_PARAM;

    id = (kcdb_identity *) vid;

    flag &= mask;

    if((mask & ~KCDB_IDENT_FLAGMASK_RDWR) ||
       ((flag & KCDB_IDENT_FLAG_INVALID) && (flag & KCDB_IDENT_FLAG_VALID)))
        return KHM_ERROR_INVALID_PARAM;

    if((mask & KCDB_IDENT_FLAG_DEFAULT) &&
       (flag & KCDB_IDENT_FLAG_DEFAULT)) {
        /* kcdb_identity_set_default already does checking for
           redundant transitions */
        rv = kcdb_identity_set_default(vid);

        if(KHM_FAILED(rv))
            return rv;

        mask &= ~KCDB_IDENT_FLAG_DEFAULT;
        flag &= ~KCDB_IDENT_FLAG_DEFAULT;
    }

    EnterCriticalSection(&cs_ident);

    if(mask & KCDB_IDENT_FLAG_SEARCHABLE) {
        if(!(flag & KCDB_IDENT_FLAG_SEARCHABLE)) {
            if(id->flags & KCDB_IDENT_FLAG_SEARCHABLE) {
                LeaveCriticalSection(&cs_ident);
                rv = kcdb_identpro_set_searchable(vid, FALSE);
                EnterCriticalSection(&cs_ident);
                if(rv == KHM_ERROR_NO_PROVIDER ||
                    KHM_SUCCEEDED(rv)) {
                    id->flags &= ~KCDB_IDENT_FLAG_SEARCHABLE;
                    delta |= KCDB_IDENT_FLAG_SEARCHABLE;
                }
            }
        } else {
            if(!(id->flags & KCDB_IDENT_FLAG_SEARCHABLE)) {
                LeaveCriticalSection(&cs_ident);
                rv = kcdb_identpro_set_searchable(vid, TRUE);
                EnterCriticalSection(&cs_ident);
                if(rv == KHM_ERROR_NO_PROVIDER ||
                    KHM_SUCCEEDED(rv)) {
                    id->flags |= KCDB_IDENT_FLAG_SEARCHABLE;
                    delta |= KCDB_IDENT_FLAG_SEARCHABLE;
                }
            }
        }

        flag &= ~KCDB_IDENT_FLAG_SEARCHABLE;
        mask &= ~KCDB_IDENT_FLAG_SEARCHABLE;
    }

    if (mask & KCDB_IDENT_FLAG_STICKY) {
        if ((flag ^ id->flags) & KCDB_IDENT_FLAG_STICKY) {
            khm_handle h_conf;

            if (KHM_SUCCEEDED(kcdb_identity_get_config(vid,
                                                       KHM_FLAG_CREATE,
                                                       &h_conf))) {
                khc_write_int32(h_conf, L"Sticky",
                                !!(flag & KCDB_IDENT_FLAG_STICKY));
                khc_close_space(h_conf);
            }

            id->flags =
                ((id->flags & ~KCDB_IDENT_FLAG_STICKY) |
                 (flag & KCDB_IDENT_FLAG_STICKY));

            delta |= KCDB_IDENT_FLAG_STICKY;
        }

        flag &= ~KCDB_IDENT_FLAG_STICKY;
        mask &= ~KCDB_IDENT_FLAG_STICKY;
    }

    /* deal with every other flag */

    oldflags = id->flags;

    id->flags = (id->flags & ~mask) | (flag & mask);

    if (flag & KCDB_IDENT_FLAG_VALID) {
        id->flags &= ~(KCDB_IDENT_FLAG_INVALID | KCDB_IDENT_FLAG_UNKNOWN);
    }
    if (flag & KCDB_IDENT_FLAG_INVALID) {
        id->flags &= ~(KCDB_IDENT_FLAG_VALID | KCDB_IDENT_FLAG_UNKNOWN);
    }

    newflags = id->flags;

    LeaveCriticalSection(&cs_ident);

    delta |= newflags ^ oldflags;

    if((delta & KCDB_IDENT_FLAG_HIDDEN)) {
        kcdbint_ident_post_message(
            (newflags & KCDB_IDENT_FLAG_HIDDEN)?KCDB_OP_HIDE:KCDB_OP_UNHIDE,
            vid);
    }

    if((delta & KCDB_IDENT_FLAG_SEARCHABLE)) {
        kcdbint_ident_post_message(
            (newflags & KCDB_IDENT_FLAG_SEARCHABLE)?KCDB_OP_SETSEARCH:KCDB_OP_UNSETSEARCH,
            vid);
    }

    if(delta != 0)
        kcdbint_ident_post_message(KCDB_OP_MODIFY, vid);

    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32 KHMAPI
kcdb_identity_get_flags(khm_handle vid,
                        khm_int32 * flags) {
    kcdb_identity * id;

    *flags = 0;

    if(!kcdb_is_active_identity(vid))
        return KHM_ERROR_INVALID_PARAM;

    id = (kcdb_identity *) vid;

    EnterCriticalSection(&cs_ident);
    *flags = id->flags;
    LeaveCriticalSection(&cs_ident);

    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32 KHMAPI
kcdb_identity_get_name(khm_handle vid,
                       wchar_t * buffer,
                       khm_size * pcbsize) {
    size_t namesize;
    kcdb_identity * id;

    if(!kcdb_is_active_identity(vid) || !pcbsize)
        return KHM_ERROR_INVALID_PARAM;

    id = (kcdb_identity *) vid;

    if(FAILED(StringCbLength(id->name, KCDB_IDENT_MAXCB_NAME, &namesize)))
        return KHM_ERROR_UNKNOWN;

    namesize += sizeof(wchar_t);

    if(!buffer || namesize > *pcbsize) {
        *pcbsize = namesize;
        return KHM_ERROR_TOO_LONG;
    }

    StringCbCopy(buffer, *pcbsize, id->name);
    *pcbsize = namesize;

    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32 KHMAPI
kcdb_identity_get_default(khm_handle * pvid) {
    khm_handle def;

    if (pvid == NULL)
        return KHM_ERROR_INVALID_PARAM;

    EnterCriticalSection(&cs_ident);
    def = kcdb_def_identity;
    if (def != NULL)
        kcdb_identity_hold(def);
    LeaveCriticalSection(&cs_ident);

    *pvid = def;

    if (def != NULL)
        return KHM_ERROR_SUCCESS;
    else
        return KHM_ERROR_NOT_FOUND;
}

static khm_int32
kcdbint_ident_set_default(khm_handle vid,
                          khm_boolean invoke_identpro) {
    kcdb_identity * new_def;
    kcdb_identity * old_def;
    khm_int32 rv;

    if (vid != NULL && !kcdb_is_active_identity(vid))
        return KHM_ERROR_INVALID_PARAM;

    new_def = (kcdb_identity *)vid;

    if (new_def != NULL && (new_def->flags & KCDB_IDENT_FLAG_DEFAULT))
        return KHM_ERROR_SUCCESS;

    if ((new_def == NULL && kcdb_def_identity == NULL) ||
        (new_def == kcdb_def_identity))
        return KHM_ERROR_SUCCESS;

    /* first check with the identity provider if this operation
       is permitted. */
    if (invoke_identpro) {
        rv = kcdb_identpro_set_default(vid);
        if(rv != KHM_ERROR_NO_PROVIDER && KHM_FAILED(rv))
            return rv;
    }

    EnterCriticalSection(&cs_ident);

    old_def = kcdb_def_identity;
    kcdb_def_identity = new_def;

    if(old_def != new_def) {
        if(old_def) {
            old_def->flags &= ~KCDB_IDENT_FLAG_DEFAULT;
            kcdb_identity_release((khm_handle) old_def);
        }

        if(new_def) {
            new_def->flags |= KCDB_IDENT_FLAG_DEFAULT;
            kcdb_identity_hold((khm_handle) new_def);
        }

        LeaveCriticalSection(&cs_ident);

        /* if (invoke_identpro) */
        kcdbint_ident_post_message(KCDB_OP_NEW_DEFAULT, new_def);
    } else {
        LeaveCriticalSection(&cs_ident);
    }

    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32 KHMAPI
kcdb_identity_set_default(khm_handle vid) {
    return kcdbint_ident_set_default(vid, TRUE);
}

KHMEXP khm_int32 KHMAPI
kcdb_identity_set_default_int(khm_handle vid) {
    return kcdbint_ident_set_default(vid, FALSE);
}

KHMEXP khm_int32 KHMAPI
kcdb_identity_get_config(khm_handle vid,
                         khm_int32 flags,
                         khm_handle * result) {
    khm_handle hkcdb;
    khm_handle hidents = NULL;
    khm_handle hident = NULL;
    khm_int32 rv;
    kcdb_identity * id;

    if(kcdb_is_active_identity(vid)) {
        id = (kcdb_identity *) vid;
    } else {
        return KHM_ERROR_INVALID_PARAM;
    }

    hkcdb = kcdb_get_config();
    if(hkcdb) {
        rv = khc_open_space(hkcdb, L"Identity", 0, &hidents);
        if(KHM_FAILED(rv))
            goto _exit;

        rv = khc_open_space(hidents,
                            id->name,
                            flags | KCONF_FLAG_NOPARSENAME,
                            &hident);

        if(KHM_FAILED(rv)) {
            khm_int32 oldflags;
            EnterCriticalSection(&cs_ident);
            oldflags = id->flags;
            id->flags &= ~KCDB_IDENT_FLAG_CONFIG;
            LeaveCriticalSection(&cs_ident);
            if (oldflags & KCDB_IDENT_FLAG_CONFIG)
                kcdbint_ident_post_message(KCDB_OP_DELCONFIG, id);
            goto _exit;
        }

        EnterCriticalSection(&cs_ident);
        id->flags |= KCDB_IDENT_FLAG_CONFIG;
        LeaveCriticalSection(&cs_ident);

        *result = hident;
    } else
        rv = KHM_ERROR_UNKNOWN;

_exit:
    if(hidents)
        khc_close_space(hidents);
    if(hkcdb)
        khc_close_space(hkcdb);
    return rv;
}

/*! \note cs_ident must be available. */
void
kcdbint_ident_post_message(khm_int32 op, kcdb_identity * id) {
    kcdb_identity_hold(id);
    kmq_post_message(KMSG_KCDB, KMSG_KCDB_IDENT, op, (void *) id);
}

/*! \note cs_ident must be available. */
KHMEXP khm_int32 KHMAPI
kcdb_identity_hold(khm_handle vid) {
    kcdb_identity * id;

    EnterCriticalSection(&cs_ident);
    if(kcdb_is_active_identity(vid)) {
        id = vid;
        id->refcount++;
    } else {
        LeaveCriticalSection(&cs_ident);
        return KHM_ERROR_INVALID_PARAM;
    }
    LeaveCriticalSection(&cs_ident);
    return ERROR_SUCCESS;
}

/*! \note cs_ident must be available. */
KHMEXP khm_int32 KHMAPI
kcdb_identity_release(khm_handle vid) {
    kcdb_identity * id;
    khm_int32 refcount;

    EnterCriticalSection(&cs_ident);
    if(kcdb_is_identity(vid)) {
        id = vid;
        refcount = --id->refcount;
        if(refcount == 0) {
            /* We only delete identities which do not have a
               configuration. */
            if (id->refcount == 0 &&
                !(id->flags & KCDB_IDENT_FLAG_CONFIG))
                kcdb_identity_delete(vid);
        }
    } else {
        LeaveCriticalSection(&cs_ident);
        return KHM_ERROR_INVALID_PARAM;
    }
    LeaveCriticalSection(&cs_ident);
    return ERROR_SUCCESS;
}

struct kcdb_idref_result {
    kcdb_identity * ident;
    khm_int32 flags;
    khm_size count;
};

static khm_int32 KHMAPI
kcdbint_idref_proc(khm_handle cred, void * r) {
    khm_handle vid;
    struct kcdb_idref_result *result;
    khm_int32 flags;

    result = (struct kcdb_idref_result *) r;

    if (KHM_SUCCEEDED(kcdb_cred_get_identity(cred, &vid))) {
        if (result->ident == (kcdb_identity *) vid) {

            result->count++;
            kcdb_cred_get_flags(cred, &flags);

            if (flags & KCDB_CRED_FLAG_RENEWABLE) {
                result->flags |= KCDB_IDENT_FLAG_CRED_RENEW;
                if (flags & KCDB_CRED_FLAG_INITIAL) {
                    result->flags |= KCDB_IDENT_FLAG_RENEWABLE;
                }
            }

            if (flags & KCDB_CRED_FLAG_EXPIRED) {
                result->flags |= KCDB_IDENT_FLAG_CRED_EXP;
                if (flags & KCDB_CRED_FLAG_INITIAL) {
                    result->flags |= KCDB_IDENT_FLAG_EXPIRED;
                }
            }

            if (flags & KCDB_CRED_FLAG_INITIAL) {
                result->flags |= KCDB_IDENT_FLAG_VALID;
            }
        }

        kcdb_identity_release(vid);
    }

    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32 KHMAPI
kcdb_identity_refresh(khm_handle vid) {
    kcdb_identity * ident;
    khm_int32 code = KHM_ERROR_SUCCESS;
    struct kcdb_idref_result result;

    EnterCriticalSection(&cs_ident);

    if (!kcdb_is_active_identity(vid)) {
        code = KHM_ERROR_INVALID_PARAM;
        goto _exit;
    }

    ident = (kcdb_identity *) vid;

    result.ident = ident;
    result.flags = 0;
    result.count = 0;

    LeaveCriticalSection(&cs_ident);

    kcdb_credset_apply(NULL, kcdbint_idref_proc, &result);

    if (result.count == 0)
        result.flags |= KCDB_IDENT_FLAG_EMPTY;

    kcdb_identity_set_flags(vid, result.flags,
                            KCDB_IDENT_FLAGMASK_RDWR &
                            ~(KCDB_IDENT_FLAG_DEFAULT |
                              KCDB_IDENT_FLAG_SEARCHABLE |
                              KCDB_IDENT_FLAG_STICKY));

    EnterCriticalSection(&cs_ident);
    ident->refresh_cycle = kcdb_ident_refresh_cycle;

 _exit:
    LeaveCriticalSection(&cs_ident);

    if (code == 0)
        code = kcdb_identpro_update(vid);

    return code;
}

KHMEXP khm_int32 KHMAPI
kcdb_identity_refresh_all(void) {
    kcdb_identity * ident;
    kcdb_identity * next;
    khm_int32 code = KHM_ERROR_SUCCESS;
    int hit_count;

    EnterCriticalSection(&cs_ident);

    kcdb_ident_refresh_cycle++;

    /* The do-while loop is here to account for race conditions.  We
       release cs_ident in the for loop, so we don't actually have a
       guarantee that we traversed the whole identity list at the end.
       We repeat until all the identities are uptodate. */

    do {
        hit_count = 0;

        for (ident = kcdb_identities;
             ident != NULL;
             ident = next) {

            if (!kcdb_is_active_identity(ident) ||
                ident->refresh_cycle == kcdb_ident_refresh_cycle) {
                next = LNEXT(ident);
                continue;
            }

            kcdb_identity_hold((khm_handle) ident);

            LeaveCriticalSection(&cs_ident);

            kcdb_identity_refresh((khm_handle) ident);

            EnterCriticalSection(&cs_ident);

            next = LNEXT(ident);
            kcdb_identity_release((khm_handle) ident);

            hit_count++;
        }

    } while (hit_count > 0);

    LeaveCriticalSection(&cs_ident);

    return code;
}

/*****************************************/
/* Custom property functions             */

KHMEXP khm_int32 KHMAPI
kcdb_identity_set_attr(khm_handle vid,
                       khm_int32 attr_id,
                       void * buffer,
                       khm_size cbbuf)
{
    kcdb_identity * id = NULL;
    kcdb_attrib * attrib = NULL;
    kcdb_type * type = NULL;
    khm_size slot;
    khm_size cbdest;
    khm_int32 code = KHM_ERROR_SUCCESS;

    EnterCriticalSection(&cs_ident);
    if(!kcdb_is_active_identity(vid)) {
        LeaveCriticalSection(&cs_ident);
        return KHM_ERROR_INVALID_PARAM;
    }

    id = (kcdb_identity *) vid;

    if(!(id->flags & KCDB_IDENT_FLAG_ATTRIBS)) {
        kcdb_buf_new(&id->buf, KCDB_BUF_DEFAULT);
        id->flags |= KCDB_IDENT_FLAG_ATTRIBS;
    }

    if(KHM_FAILED(kcdb_attrib_get_info(attr_id, &attrib))) {
        LeaveCriticalSection(&cs_ident);
        return KHM_ERROR_INVALID_PARAM;
    }

#if 0
    /* actually, even if an attribute is computed, we still allow
       those values to be set.  This is because computing values
       is only for credentials.  If a computed value is used as a
       property in any other object, it is treated as a regular value
       */
    if(attrib->flags & KCDB_ATTR_FLAG_COMPUTED)
    {
        LeaveCriticalSection(&cs_ident);
        kcdb_attrib_release_info(attrib);
        return KHM_ERROR_INVALID_OPERATION;
    }
#endif

    if (buffer == NULL) {
        /* we are removing a value */
        slot = kcdb_buf_slot_by_id(&id->buf, (khm_ui_2) attr_id);
        if (slot != KCDB_BUF_INVALID_SLOT &&
            kcdb_buf_exist(&id->buf, slot))
            kcdb_buf_alloc(&id->buf, slot, (khm_ui_2) attr_id, 0);
        code = KHM_ERROR_SUCCESS;
        goto _exit;
    }

    if(KHM_FAILED(kcdb_type_get_info(attrib->type, &type))) {
        LeaveCriticalSection(&cs_ident);
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

    kcdb_buf_alloc(&id->buf, KCDB_BUF_APPEND, (khm_ui_2) attr_id, cbdest);
    slot = kcdb_buf_slot_by_id(&id->buf, (khm_ui_2) attr_id);
    if(slot == KCDB_BUF_INVALID_SLOT || !kcdb_buf_exist(&id->buf, slot)) {
        code = KHM_ERROR_NO_RESOURCES;
        goto _exit;
    }

    if(KHM_FAILED(code =
        type->dup(buffer, cbbuf, kcdb_buf_get(&id->buf, slot), &cbdest)))
    {
        kcdb_buf_alloc(&id->buf, slot, (khm_ui_2) attr_id, 0);
        goto _exit;
    }

    kcdb_buf_set_value_flag(&id->buf, slot);

_exit:
    LeaveCriticalSection(&cs_ident);

    if(attrib)
        kcdb_attrib_release_info(attrib);
    if(type)
        kcdb_type_release_info(type);

    return code;
}

KHMEXP khm_int32 KHMAPI
kcdb_identity_set_attrib(khm_handle vid,
                         const wchar_t * attr_name,
                         void * buffer,
                         khm_size cbbuf)
{
    khm_int32 attr_id = -1;

    if(KHM_FAILED(kcdb_attrib_get_id(attr_name, &attr_id)))
        return KHM_ERROR_INVALID_PARAM;

    return kcdb_identity_set_attr(
        vid,
        attr_id,
        buffer,
        cbbuf);
}

KHMEXP khm_int32 KHMAPI
kcdb_identity_get_attr(khm_handle vid,
                       khm_int32 attr_id,
                       khm_int32 * attr_type,
                       void * buffer,
                       khm_size * pcbbuf)
{
    khm_int32 code = KHM_ERROR_SUCCESS;
    kcdb_identity * id = NULL;
    kcdb_attrib * attrib = NULL;
    kcdb_type * type = NULL;
    khm_size slot;

    if(KHM_FAILED(kcdb_attrib_get_info(attr_id, &attrib))) {
        return KHM_ERROR_INVALID_PARAM;
    }

    if(KHM_FAILED(kcdb_type_get_info(attrib->type, &type))) {
        kcdb_attrib_release_info(attrib);
        return KHM_ERROR_UNKNOWN;
    }

    if(attr_type)
        *attr_type = attrib->type;

    EnterCriticalSection(&cs_ident);

    if(!kcdb_is_active_identity(vid)) {
        code = KHM_ERROR_INVALID_PARAM;
        goto _exit;
    }

    id = (kcdb_identity *) vid;

    if(!(id->flags & KCDB_IDENT_FLAG_ATTRIBS) ||
       (slot = kcdb_buf_slot_by_id(&id->buf, (khm_ui_2) attr_id)) == KCDB_BUF_INVALID_SLOT ||
        !kcdb_buf_val_exist(&id->buf, slot))
    {
        code = KHM_ERROR_NOT_FOUND;
        goto _exit;
    }

    if(!buffer && !pcbbuf) {
        /* in this case the caller is only trying to determine if the field
            contains data.  If we get here, then the value exists. */
        code = KHM_ERROR_SUCCESS;
        goto _exit;
    }

#if 0
    if(attrib->flags & KCDB_ATTR_FLAG_COMPUTED) {
        /* we should never hit this case */
#ifdef DEBUG
        assert(FALSE);
#endif
        code = KHM_ERROR_INVALID_OPERATION;
    } else {
#endif
        code = type->dup(
            kcdb_buf_get(&id->buf, slot),
            kcdb_buf_size(&id->buf, slot),
            buffer,
            pcbbuf);
#if 0
    }
#endif

_exit:
    LeaveCriticalSection(&cs_ident);
    if(type)
        kcdb_type_release_info(type);
    if(attrib)
        kcdb_attrib_release_info(attrib);

    return code;
}

KHMEXP khm_int32 KHMAPI
kcdb_identity_get_attrib(khm_handle vid,
                         const wchar_t * attr_name,
                         khm_int32 * attr_type,
                         void * buffer,
                         khm_size * pcbbuf)
{
    khm_int32 attr_id = -1;

    if(KHM_FAILED(kcdb_attrib_get_id(attr_name, &attr_id)))
        return KHM_ERROR_NOT_FOUND;

    return kcdb_identity_get_attr(vid,
                                  attr_id,
                                  attr_type,
                                  buffer,
                                  pcbbuf);
}

KHMEXP khm_int32 KHMAPI
kcdb_identity_get_attr_string(khm_handle vid,
                              khm_int32 attr_id,
                              wchar_t * buffer,
                              khm_size * pcbbuf,
                              khm_int32 flags)
{
    khm_int32 code = KHM_ERROR_SUCCESS;
    kcdb_identity * id = NULL;
    kcdb_attrib * attrib = NULL;
    kcdb_type * type = NULL;
    khm_size slot;

    if(KHM_FAILED(kcdb_attrib_get_info(attr_id, &attrib))) {
        return KHM_ERROR_INVALID_PARAM;
    }

    if(KHM_FAILED(kcdb_type_get_info(attrib->type, &type))) {
        kcdb_attrib_release_info(attrib);
        return KHM_ERROR_UNKNOWN;
    }

    EnterCriticalSection(&cs_ident);

    if(!kcdb_is_active_identity(vid)) {
        code = KHM_ERROR_INVALID_PARAM;
        goto _exit;
    }

    id = (kcdb_identity *) vid;

    if(!(id->flags & KCDB_IDENT_FLAG_ATTRIBS) ||
       (slot = kcdb_buf_slot_by_id(&id->buf, (khm_ui_2) attr_id)) == KCDB_BUF_INVALID_SLOT ||
        !kcdb_buf_val_exist(&id->buf, slot))
    {
        code = KHM_ERROR_NOT_FOUND;
        goto _exit;
    }

    if(!buffer && !pcbbuf) {
        /* in this case the caller is only trying to determine if the field
            contains data.  If we get here, then the value exists */
        code = KHM_ERROR_SUCCESS;
        goto _exit;
    }

#if 0
    if(attrib->flags & KCDB_ATTR_FLAG_COMPUTED) {
#ifdef DEBUG
        assert(FALSE);
#endif
        code = KHM_ERROR_INVALID_OPERATION;
    } else {
#endif
        if(kcdb_buf_exist(&id->buf, slot)) {
            code = type->toString(
                kcdb_buf_get(&id->buf, slot),
                kcdb_buf_size(&id->buf, slot),
                buffer,
                pcbbuf,
                flags);
        } else
            code = KHM_ERROR_NOT_FOUND;
#if 0
    }
#endif

_exit:
    LeaveCriticalSection(&cs_ident);
    if(type)
        kcdb_type_release_info(type);
    if(attrib)
        kcdb_attrib_release_info(attrib);

    return code;
}

KHMEXP khm_int32 KHMAPI
kcdb_identity_get_attrib_string(khm_handle vid,
                                const wchar_t * attr_name,
                                wchar_t * buffer,
                                khm_size * pcbbuf,
                                khm_int32 flags)
{
    khm_int32 attr_id = -1;

    if(KHM_FAILED(kcdb_attrib_get_id(attr_name, &attr_id)))
        return KHM_ERROR_NOT_FOUND;

    return kcdb_identity_get_attr_string(
        vid,
        attr_id,
        buffer,
        pcbbuf,
        flags);
}

/*****************************************/
/* Identity provider interface functions */

/* NOT called with cs_ident held */
KHMEXP khm_int32 KHMAPI
kcdb_identpro_validate_name(const wchar_t * name)
{
    kcdb_ident_name_xfer namex;
    khm_handle sub;
    khm_size cch;
    khm_int32 rv = KHM_ERROR_SUCCESS;

    /* we need to verify the length and the contents of the string
       before calling the identity provider */
    if(FAILED(StringCchLength(name, KCDB_IDENT_MAXCCH_NAME, &cch)))
        return KHM_ERROR_TOO_LONG;

    /* We can't really make an assumption about the valid characters
       in an identity.  So we let the identity provider decide */
#ifdef VALIDATE_IDENTIY_CHARACTERS
    if(wcsspn(name, KCDB_IDENT_VALID_CHARS) != cch)
        return KHM_ERROR_INVALID_NAME;
#endif

    EnterCriticalSection(&cs_ident);
    if(kcdb_ident_sub != NULL) {
        sub = kcdb_ident_sub;
    } else {
        sub = NULL;
        rv = KHM_ERROR_NO_PROVIDER;
    }
    LeaveCriticalSection(&cs_ident);

    if(sub != NULL) {
        ZeroMemory(&namex, sizeof(namex));

        namex.name_src = name;
        namex.result = KHM_ERROR_NOT_IMPLEMENTED;

        kmq_send_sub_msg(sub,
                         KMSG_IDENT,
                         KMSG_IDENT_VALIDATE_NAME,
                         0,
                         (void *) &namex);

        rv = namex.result;
    }

    return rv;
}

KHMEXP khm_int32 KHMAPI
kcdb_identpro_validate_identity(khm_handle identity)
{
    khm_int32 rv = KHM_ERROR_SUCCESS;
    khm_handle sub;

    if(!kcdb_is_active_identity(identity))
        return KHM_ERROR_INVALID_PARAM;

    EnterCriticalSection(&cs_ident);
    if(kcdb_ident_sub != NULL) {
        sub = kcdb_ident_sub;
    } else {
        sub = NULL;
        rv = KHM_ERROR_NO_PROVIDER;
    }
    LeaveCriticalSection(&cs_ident);

    if(sub != NULL) {
        rv = kmq_send_sub_msg(sub,
                              KMSG_IDENT,
                              KMSG_IDENT_VALIDATE_IDENTITY,
                              0,
                              (void *) identity);
    }

    return rv;
}

KHMEXP khm_int32 KHMAPI
kcdb_identpro_canon_name(const wchar_t * name_in,
                         wchar_t * name_out,
                         khm_size * cb_name_out)
{
    khm_handle sub;
    kcdb_ident_name_xfer namex;
    wchar_t name_tmp[KCDB_IDENT_MAXCCH_NAME];
    khm_int32 rv = KHM_ERROR_SUCCESS;
    khm_size cch;

    if(cb_name_out == 0 ||
       FAILED(StringCchLength(name_in, KCDB_IDENT_MAXCCH_NAME, &cch)))
        return KHM_ERROR_INVALID_NAME;

    EnterCriticalSection(&cs_ident);
    if(kcdb_ident_sub != NULL) {
        sub = kcdb_ident_sub;
    } else {
        sub = NULL;
        rv = KHM_ERROR_NO_PROVIDER;
    }
    LeaveCriticalSection(&cs_ident);

    if(sub != NULL) {
        ZeroMemory(&namex, sizeof(namex));
        ZeroMemory(name_tmp, sizeof(name_tmp));

        namex.name_src = name_in;
        namex.name_dest = name_tmp;
        namex.cb_name_dest = sizeof(name_tmp);
        namex.result = KHM_ERROR_NOT_IMPLEMENTED;

        rv = kmq_send_sub_msg(sub,
                              KMSG_IDENT,
                              KMSG_IDENT_CANON_NAME,
                              0,
                              (void *) &namex);

        if(KHM_SUCCEEDED(namex.result)) {
            const wchar_t * name_result;
            khm_size cb;

            if(name_in[0] != 0 && name_tmp[0] == 0)
                name_result = name_tmp;
            else
                name_result = name_in;

            if(FAILED(StringCbLength(name_result, KCDB_IDENT_MAXCB_NAME, &cb)))
                rv = KHM_ERROR_UNKNOWN;
            else {
                cb += sizeof(wchar_t);
                if(name_out == 0 || *cb_name_out < cb) {
                    rv = KHM_ERROR_TOO_LONG;
                    *cb_name_out = cb;
                } else {
                    StringCbCopy(name_out, *cb_name_out, name_result);
                    *cb_name_out = cb;
                    rv = KHM_ERROR_SUCCESS;
                }
            }
        }
    }

    return rv;
}

KHMEXP khm_int32 KHMAPI
kcdb_identpro_compare_name(const wchar_t * name1,
                           const wchar_t * name2)
{
    khm_handle sub;
    kcdb_ident_name_xfer namex;
    khm_int32 rv = 0;

    /* Generally in kcdb_identpro_* functions we don't emulate
       any behavior if the provider is not available, but lacking
       a way to make this known, we emulate here */
    rv = wcscmp(name1, name2);

    EnterCriticalSection(&cs_ident);
    if(kcdb_ident_sub != NULL) {
        sub = kcdb_ident_sub;
    } else {
        sub = NULL;
    }
    LeaveCriticalSection(&cs_ident);

    if(sub != NULL) {
        ZeroMemory(&namex, sizeof(namex));
        namex.name_src = name1;
        namex.name_alt = name2;
        namex.result = rv;

        kmq_send_sub_msg(sub,
                         KMSG_IDENT,
                         KMSG_IDENT_COMPARE_NAME,
                         0,
                         (void *) &namex);

        rv = namex.result;
    }

    return rv;
}

KHMEXP khm_int32 KHMAPI
kcdb_identpro_set_default(khm_handle identity)
{
    khm_handle sub;
    khm_int32 rv = KHM_ERROR_SUCCESS;

    if((identity != NULL) &&
       !kcdb_is_active_identity(identity))
        return KHM_ERROR_INVALID_PARAM;

    EnterCriticalSection(&cs_ident);
    if(kcdb_ident_sub != NULL) {
        sub = kcdb_ident_sub;
    } else {
        sub = NULL;
        rv = KHM_ERROR_NO_PROVIDER;
    }
    LeaveCriticalSection(&cs_ident);

    if(sub != NULL) {
        rv = kmq_send_sub_msg(sub,
                              KMSG_IDENT,
                              KMSG_IDENT_SET_DEFAULT,
                              (identity != NULL),
                              (void *) identity);
    }

    return rv;
}

KHMEXP khm_int32 KHMAPI
kcdb_identpro_set_searchable(khm_handle identity,
                             khm_boolean searchable)
{
    khm_handle sub;
	khm_int32 rv = KHM_ERROR_SUCCESS;

	if(!kcdb_is_active_identity(identity))
		return KHM_ERROR_INVALID_PARAM;

	EnterCriticalSection(&cs_ident);
	if(kcdb_ident_sub != NULL) {
        sub = kcdb_ident_sub;
	} else {
        sub = NULL;
		rv = KHM_ERROR_NO_PROVIDER;
	}
	LeaveCriticalSection(&cs_ident);

    if(sub != NULL) {
        rv = kmq_send_sub_msg(
                              sub,
                              KMSG_IDENT,
                              KMSG_IDENT_SET_SEARCHABLE,
                              searchable,
                              (void *) identity);
    }

	return rv;
}


KHMEXP khm_int32 KHMAPI
kcdb_identpro_update(khm_handle identity)
{
    khm_handle sub;
    khm_int32 rv = KHM_ERROR_SUCCESS;

    if(!kcdb_is_active_identity(identity))
        return KHM_ERROR_INVALID_PARAM;

    EnterCriticalSection(&cs_ident);
    if(kcdb_ident_sub != NULL) {
        sub = kcdb_ident_sub;
    } else {
        sub = NULL;
        rv = KHM_ERROR_NO_PROVIDER;
    }
    LeaveCriticalSection(&cs_ident);

    if(sub != NULL) {
        rv = kmq_send_sub_msg(sub,
                              KMSG_IDENT,
                              KMSG_IDENT_UPDATE,
                              0,
                              (void *) identity);
    }

    return rv;
}

KHMEXP khm_int32 KHMAPI
kcdb_identpro_notify_create(khm_handle identity)
{
    khm_handle sub;
    khm_int32 rv = KHM_ERROR_SUCCESS;

    if(!kcdb_is_active_identity(identity))
        return KHM_ERROR_INVALID_PARAM;

    EnterCriticalSection(&cs_ident);
    if(kcdb_ident_sub != NULL) {
        sub = kcdb_ident_sub;
    } else {
        sub = NULL;
        rv = KHM_ERROR_NO_PROVIDER;
    }
    LeaveCriticalSection(&cs_ident);

    if(sub != NULL) {
        rv = kmq_send_sub_msg(
            sub,
            KMSG_IDENT,
            KMSG_IDENT_NOTIFY_CREATE,
            0,
            (void *) identity);
    }

    return rv;
}

KHMEXP khm_int32 KHMAPI
kcdb_identpro_get_ui_cb(void * rock)
{
    khm_handle sub;
    khm_int32 rv = KHM_ERROR_SUCCESS;

    EnterCriticalSection(&cs_ident);
    if(kcdb_ident_sub != NULL) {
        sub = kcdb_ident_sub;
    } else {
        sub = NULL;
        rv = KHM_ERROR_NO_PROVIDER;
    }
    LeaveCriticalSection(&cs_ident);

    if(sub != NULL) {
        rv = kmq_send_sub_msg(
            sub,
            KMSG_IDENT,
            KMSG_IDENT_GET_UI_CALLBACK,
            0,
            rock);
    }

    return rv;
}

KHMEXP khm_int32 KHMAPI
kcdb_identity_enum(khm_int32 and_flags,
                   khm_int32 eq_flags,
                   wchar_t * name_buf,
                   khm_size * pcb_buf,
                   khm_size * pn_idents)
{
    kcdb_identity * id;
    khm_int32 rv = KHM_ERROR_SUCCESS;
    khm_size cb_req = 0;
    khm_size n_idents = 0;
    size_t cb_curr;
    size_t cch_curr;
    size_t cch_left;
    HRESULT hr;

    if ((name_buf == NULL && pcb_buf == NULL && pn_idents == NULL) ||
        (name_buf != NULL && pcb_buf == NULL))
        return KHM_ERROR_INVALID_PARAM;

    eq_flags &= and_flags;

    EnterCriticalSection(&cs_ident);

    if (!kcdb_checked_config) {
        khm_handle h_kcdb = NULL;
        khm_handle h_idents = NULL;
        khm_handle h_ident = NULL;

        kcdb_checked_config = TRUE;
        kcdb_checking_config = TRUE;

        h_kcdb = kcdb_get_config();
        if (!h_kcdb)
            goto _config_check_cleanup;
        if(KHM_FAILED(khc_open_space(h_kcdb, L"Identity", 0, &h_idents)))
            goto _config_check_cleanup;

        while(KHM_SUCCEEDED(khc_enum_subspaces(h_idents,
                                               h_ident,
                                               &h_ident))) {

            wchar_t wname[KCDB_IDENT_MAXCCH_NAME];
            khm_size cb;
            khm_handle t_id;

            cb = sizeof(wname);
            if (KHM_FAILED(khc_get_config_space_name(h_ident,
                                                     wname,
                                                     &cb)))
                continue;

            LeaveCriticalSection(&cs_ident);

            if (KHM_SUCCEEDED(kcdb_identity_create(wname,
                                                   KCDB_IDENT_FLAG_CREATE,
                                                   &t_id)))
                kcdb_identity_release(t_id);

            EnterCriticalSection(&cs_ident);
        }

    _config_check_cleanup:
        if (h_kcdb)
            khc_close_space(h_kcdb);
        if (h_idents)
            khc_close_space(h_idents);

        kcdb_checking_config = FALSE;
    }

    for ( id = kcdb_identities;
          id != NULL;
          id = LNEXT(id) ) {
        if (((id->flags & KCDB_IDENT_FLAG_ACTIVE) ==
             KCDB_IDENT_FLAG_ACTIVE) &&
            ((id->flags & and_flags) == eq_flags)) {
            n_idents ++;
            hr = StringCbLength(id->name, KCDB_IDENT_MAXCB_NAME, &cb_curr);
#ifdef DEBUG
            assert(SUCCEEDED(hr));
#endif
            cb_req += cb_curr + sizeof(wchar_t);
        }
    }

    cb_req += sizeof(wchar_t);

    if (pn_idents != NULL)
        *pn_idents = n_idents;

    if (pcb_buf != NULL && (name_buf == NULL || *pcb_buf < cb_req)) {
        *pcb_buf = cb_req;

        rv = KHM_ERROR_TOO_LONG;
    } else if(name_buf != NULL) {
        cch_left = (*pcb_buf) / sizeof(wchar_t);

        for (id = kcdb_identities;
             id != NULL;
             id = LNEXT(id)) {
            if (((id->flags & KCDB_IDENT_FLAG_ACTIVE) ==
                 KCDB_IDENT_FLAG_ACTIVE) &&
                ((id->flags & and_flags) == eq_flags)) {
                StringCchLength(id->name, KCDB_IDENT_MAXCCH_NAME,
                                &cch_curr);
                cch_curr++;
                StringCchCopy(name_buf, cch_left, id->name);
                cch_left -= cch_curr;
                name_buf += cch_curr;
            }
        }

        *name_buf = L'\0';
        *pcb_buf = cb_req;
    }

    LeaveCriticalSection(&cs_ident);

    return rv;
}
