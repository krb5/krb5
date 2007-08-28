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

#define _NIMLIB_

#include<khuidefs.h>
#include<utils.h>
#include<assert.h>
#include<strsafe.h>

#define CW_ALLOC_INCR 8

static void cw_free_prompts(khui_new_creds * c);

static void cw_free_prompt(khui_new_creds_prompt * p);

static khui_new_creds_prompt * 
cw_create_prompt(
    khm_size idx,
    khm_int32 type,
    wchar_t * prompt,
    wchar_t * def,
    khm_int32 flags);

KHMEXP khm_int32 KHMAPI 
khui_cw_create_cred_blob(khui_new_creds ** ppnc)
{
    khui_new_creds * c;

    c = PMALLOC(sizeof(*c));
    ZeroMemory(c, sizeof(*c));

    c->magic = KHUI_NC_MAGIC;
    InitializeCriticalSection(&c->cs);
    c->result = KHUI_NC_RESULT_CANCEL;
    c->mode = KHUI_NC_MODE_MINI;

    khui_context_create(&c->ctx, KHUI_SCOPE_NONE, NULL, KCDB_CREDTYPE_INVALID, NULL);

    *ppnc = c;

    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32 KHMAPI 
khui_cw_destroy_cred_blob(khui_new_creds *c)
{
    khm_size i;
    size_t len;
    EnterCriticalSection(&c->cs);
    for(i=0;i<c->n_identities;i++) {
        kcdb_identity_release(c->identities[i]);
    }
    cw_free_prompts(c);
    khui_context_release(&c->ctx);
    LeaveCriticalSection(&c->cs);
    DeleteCriticalSection(&c->cs);

    if (c->password) {
        len = wcslen(c->password);
        SecureZeroMemory(c->password, sizeof(wchar_t) * len);
        PFREE(c->password);
    }

    if (c->identities)
        PFREE(c->identities);

    if (c->types)
        PFREE(c->types);

    if (c->type_subs)
        PFREE(c->type_subs);

    if (c->window_title)
        PFREE(c->window_title);

    PFREE(c);

    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32 KHMAPI 
khui_cw_lock_nc(khui_new_creds * c)
{
    EnterCriticalSection(&c->cs);
    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32 KHMAPI 
khui_cw_unlock_nc(khui_new_creds * c)
{
    LeaveCriticalSection(&c->cs);
    return KHM_ERROR_SUCCESS;
}

#define NC_N_IDENTITIES 4

KHMEXP khm_int32 KHMAPI 
khui_cw_add_identity(khui_new_creds * c, 
                     khm_handle id)
{
    if(id == NULL)
        return KHM_ERROR_SUCCESS; /* we return success because adding
                                  a NULL id is equivalent to adding
                                  nothing. */
    EnterCriticalSection(&(c->cs));

    if(c->identities == NULL) {
        c->nc_identities = NC_N_IDENTITIES;
        c->identities = PMALLOC(sizeof(*(c->identities)) * 
                               c->nc_identities);
        c->n_identities = 0;
    } else if(c->n_identities + 1 > c->nc_identities) {
        khm_handle * ni;

        c->nc_identities = UBOUNDSS(c->n_identities + 1, 
                                    NC_N_IDENTITIES, 
                                    NC_N_IDENTITIES);
        ni = PMALLOC(sizeof(*(c->identities)) * c->nc_identities);
        memcpy(ni, c->identities, 
               sizeof(*(c->identities)) * c->n_identities);
        PFREE(c->identities);
        c->identities = ni;
    }

    kcdb_identity_hold(id);
    c->identities[c->n_identities++] = id;
    LeaveCriticalSection(&(c->cs));

    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32 KHMAPI 
khui_cw_set_primary_id(khui_new_creds * c, 
                       khm_handle id)
{
    khm_size  i;
    khm_int32 rv;

    EnterCriticalSection(&c->cs);

    /* no change */
    if((c->n_identities > 0 && c->identities[0] == id) ||
       (c->n_identities == 0 && id == NULL)) {
        LeaveCriticalSection(&c->cs);
        return KHM_ERROR_SUCCESS;
    }

    for(i=0; i<c->n_identities; i++) {
        kcdb_identity_release(c->identities[i]);
    }
    c->n_identities = 0;

    LeaveCriticalSection(&(c->cs));
    rv = khui_cw_add_identity(c,id);
    if(c->hwnd != NULL) {
        PostMessage(c->hwnd, KHUI_WM_NC_NOTIFY, 
                    MAKEWPARAM(0, WMNC_IDENTITY_CHANGE), 0);
    }
    return rv;
}

KHMEXP khm_int32 KHMAPI 
khui_cw_add_type(khui_new_creds * c, 
                 khui_new_creds_by_type * t)
{
    EnterCriticalSection(&c->cs);

    if(c->n_types >= KHUI_MAX_NCTYPES) {
        LeaveCriticalSection(&c->cs);
        return KHM_ERROR_OUT_OF_BOUNDS;
    }

    if(c->types == NULL) {
        c->nc_types = CW_ALLOC_INCR;
        c->types = PMALLOC(sizeof(*(c->types)) * c->nc_types);
        c->type_subs = PMALLOC(sizeof(*(c->type_subs)) * c->nc_types);
        c->n_types = 0;
    }

    if(c->nc_types < c->n_types + 1) {
        void * t;
        khm_size n;

        n = UBOUNDSS(c->n_types + 1, CW_ALLOC_INCR, CW_ALLOC_INCR);

        t = PMALLOC(sizeof(*(c->types)) * n);
        memcpy(t, (void *) c->types, sizeof(*(c->types)) * c->n_types);
        PFREE(c->types);
        c->types = t;

        t = PMALLOC(sizeof(*(c->type_subs)) * n);
        memcpy(t, (void *) c->type_subs, sizeof(*(c->type_subs)) * c->n_types);
        PFREE(c->type_subs);
        c->type_subs = t;

        c->nc_types = n;
    }

    c->type_subs[c->n_types] = kcdb_credtype_get_sub(t->type);
    c->types[c->n_types++] = t;
    t->nc = c;
    LeaveCriticalSection(&c->cs);
    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32 KHMAPI 
khui_cw_del_type(khui_new_creds * c, 
                 khm_int32 type_id)
{
    khm_size  i;

    EnterCriticalSection(&c->cs);
    for(i=0; i < c->n_types; i++) {
        if(c->types[i]->type == type_id)
            break;
    }
    if(i >= c->n_types) {
        LeaveCriticalSection(&c->cs);
        return KHM_ERROR_NOT_FOUND;
    }
    c->n_types--;
    for(;i < c->n_types; i++) {
        c->types[i] = c->types[i+1];
        c->type_subs[i] = c->type_subs[i+1];
    }
    LeaveCriticalSection(&c->cs);
    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32 KHMAPI 
khui_cw_find_type(khui_new_creds * c, 
                  khm_int32 type, 
                  khui_new_creds_by_type **t)
{
    khm_size i;

    EnterCriticalSection(&c->cs);
    *t = NULL;
    for(i=0;i<c->n_types;i++) {
        if(c->types[i]->type == type) {
            *t = c->types[i];
            break;
        }
    }
    LeaveCriticalSection(&c->cs);

    if(*t)
        return KHM_ERROR_SUCCESS;
    return KHM_ERROR_NOT_FOUND;
}


KHMEXP khm_int32 KHMAPI 
khui_cw_enable_type(khui_new_creds * c,
                    khm_int32 type,
                    khm_boolean enable)
{
    khui_new_creds_by_type * t = NULL;
    BOOL delta = FALSE;

    EnterCriticalSection(&c->cs);
    if(KHM_SUCCEEDED(khui_cw_find_type(c, type, &t))) {
        if(enable) {
            delta = t->flags & KHUI_NCT_FLAG_DISABLED;
            t->flags &= ~KHUI_NCT_FLAG_DISABLED;
        }
        else {
            delta = !(t->flags & KHUI_NCT_FLAG_DISABLED);
            t->flags |= KHUI_NCT_FLAG_DISABLED;
        }
    }
    LeaveCriticalSection(&c->cs);

    if(delta)
        PostMessage(c->hwnd, KHUI_WM_NC_NOTIFY, MAKEWPARAM(0,WMNC_TYPE_STATE), (LPARAM) type);

    return (t)?KHM_ERROR_SUCCESS:KHM_ERROR_NOT_FOUND;
}

KHMEXP khm_boolean KHMAPI 
khui_cw_type_succeeded(khui_new_creds * c,
                       khm_int32 type)
{
    khui_new_creds_by_type * t;
    khm_boolean s;

    EnterCriticalSection(&c->cs);
    if(KHM_SUCCEEDED(khui_cw_find_type(c, type, &t))) {
        s = (t->flags & KHUI_NCT_FLAG_PROCESSED) && !(t->flags & KHUI_NC_RESPONSE_FAILED);
    } else {
        s = FALSE;
    }
    LeaveCriticalSection(&c->cs);

    return s;
}

static khui_new_creds_prompt * 
cw_create_prompt(khm_size idx,
                 khm_int32 type,
                 wchar_t * prompt,
                 wchar_t * def,
                 khm_int32 flags)
{
    khui_new_creds_prompt * p;
    size_t cb_prompt = 0;
    size_t cb_def = 0;

    if(prompt && FAILED(StringCbLength(prompt, KHUI_MAXCB_PROMPT, &cb_prompt)))
        return NULL;
    if(def && FAILED(StringCbLength(def, KHUI_MAXCB_PROMPT_VALUE, &cb_def)))
        return NULL;

    p = PMALLOC(sizeof(*p));
    ZeroMemory(p, sizeof(*p));

    if(prompt) {
        cb_prompt += sizeof(wchar_t);
        p->prompt = PMALLOC(cb_prompt);
        StringCbCopy(p->prompt, cb_prompt, prompt);
    }

    if(def && cb_def > 0) {
        cb_def += sizeof(wchar_t);
        p->def = PMALLOC(cb_def);
        StringCbCopy(p->def, cb_def, def);
    }

    p->value = PMALLOC(KHUI_MAXCB_PROMPT_VALUE);
    ZeroMemory(p->value, KHUI_MAXCB_PROMPT_VALUE);

    p->type = type;
    p->flags = flags;
    p->index = idx;

    return p;
}

static void 
cw_free_prompt(khui_new_creds_prompt * p) {
    size_t cb;

    if(p->prompt) {
        if(SUCCEEDED(StringCbLength(p->prompt, KHUI_MAXCB_PROMPT, &cb)))
            SecureZeroMemory(p->prompt, cb);
        PFREE(p->prompt);
    }

    if(p->def) {
        if(SUCCEEDED(StringCbLength(p->def, KHUI_MAXCB_PROMPT, &cb)))
            SecureZeroMemory(p->def, cb);
        PFREE(p->def);
    }

    if(p->value) {
        if(SUCCEEDED(StringCbLength(p->value, KHUI_MAXCB_PROMPT_VALUE, &cb)))
            SecureZeroMemory(p->value, cb);
        PFREE(p->value);
    }

    PFREE(p);
}

static void 
cw_free_prompts(khui_new_creds * c)
{
    khm_size i;

    if(c->banner != NULL) {
        PFREE(c->banner);
        c->banner = NULL;
    }

    if(c->pname != NULL) {
        PFREE(c->pname);
        c->pname = NULL;
    }

    for(i=0;i < c->n_prompts; i++) {
        if(c->prompts[i]) {
            cw_free_prompt(c->prompts[i]);
            c->prompts[i] = NULL;
        }
    }

    if(c->prompts != NULL) {
        PFREE(c->prompts);
        c->prompts = NULL;
    }

    c->nc_prompts = 0;
    c->n_prompts = 0;
}

KHMEXP khm_int32 KHMAPI 
khui_cw_clear_prompts(khui_new_creds * c)
{
    /* the WMNC_CLEAR_PROMPT message needs to be sent before freeing
       the prompts, because the prompts structure still holds the
       window handles for the custom prompt controls. */
    SendMessage(c->hwnd, KHUI_WM_NC_NOTIFY, 
                MAKEWPARAM(0,WMNC_CLEAR_PROMPTS), (LPARAM) c);

    EnterCriticalSection(&c->cs);
    cw_free_prompts(c);
    LeaveCriticalSection(&c->cs);

    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32 KHMAPI 
khui_cw_begin_custom_prompts(khui_new_creds * c, 
                             khm_size n_prompts, 
                             wchar_t * banner, 
                             wchar_t * pname)
{
    size_t cb;

    PostMessage(c->hwnd, KHUI_WM_NC_NOTIFY, 
                MAKEWPARAM(0,WMNC_CLEAR_PROMPTS), (LPARAM) c);

    EnterCriticalSection(&c->cs);
#ifdef DEBUG
    assert(c->n_prompts == 0);
#endif
    cw_free_prompts(c);

    if(SUCCEEDED(StringCbLength(banner, KHUI_MAXCB_BANNER, &cb)) && 
       cb > 0) {
        cb += sizeof(wchar_t);
        c->banner = PMALLOC(cb);
        StringCbCopy(c->banner, cb, banner);
    } else {
        c->banner = NULL;
    }

    if(SUCCEEDED(StringCbLength(pname, KHUI_MAXCB_PNAME, &cb)) && 
       cb > 0) {

        cb += sizeof(wchar_t);
        c->pname = PMALLOC(cb);
        StringCbCopy(c->pname, cb, pname);

    } else {

        c->pname = NULL;

    }

    if(n_prompts > 0) {
        c->prompts = PMALLOC(sizeof(*(c->prompts)) * n_prompts);
        ZeroMemory(c->prompts, sizeof(*(c->prompts)) * n_prompts);
        c->nc_prompts = n_prompts;
        c->n_prompts = 0;

    } else {

        c->prompts = NULL;
        c->n_prompts = 0;
        c->nc_prompts = 0;

        PostMessage(c->hwnd, KHUI_WM_NC_NOTIFY, 
                    MAKEWPARAM(0, WMNC_SET_PROMPTS), (LPARAM) c);
    }

    LeaveCriticalSection(&c->cs);

    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32 KHMAPI 
khui_cw_add_prompt(khui_new_creds * c, 
                   khm_int32 type, 
                   wchar_t * prompt, 
                   wchar_t * def, 
                   khm_int32 flags)
{
    khui_new_creds_prompt * p;

    if(c->nc_prompts == 0 ||
        c->n_prompts == c->nc_prompts)
        return KHM_ERROR_INVALID_OPERATION;

#ifdef DEBUG
    assert(c->prompts != NULL);
#endif

    EnterCriticalSection(&c->cs);
    p = cw_create_prompt(c->n_prompts, type, prompt, def, flags);
    if(p == NULL) {
        LeaveCriticalSection(&c->cs);
        return KHM_ERROR_INVALID_PARAM;
    }
    c->prompts[c->n_prompts++] = p;
    LeaveCriticalSection(&c->cs);

    if(c->n_prompts == c->nc_prompts) {
        PostMessage(c->hwnd, KHUI_WM_NC_NOTIFY, 
                    MAKEWPARAM(0, WMNC_SET_PROMPTS), (LPARAM) c);
        /* once we are done adding prompts, switch to the auth
           panel */
#if 0
        /* Actually, don't. Doing so can mean an unexpected panel
           switch if fiddling on some other panel causes a change in
           custom prompts. */
        SendMessage(c->hwnd, KHUI_WM_NC_NOTIFY, 
                    MAKEWPARAM(0, WMNC_DIALOG_SWITCH_PANEL), 
                    (LPARAM) c);
#endif
    }

    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32 KHMAPI 
khui_cw_get_prompt_count(khui_new_creds * c,
                         khm_size * np) {

    EnterCriticalSection(&c->cs);
    *np = c->n_prompts;
    LeaveCriticalSection(&c->cs);

    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32 KHMAPI 
khui_cw_get_prompt(khui_new_creds * c, 
                   khm_size idx, 
                   khui_new_creds_prompt ** prompt)
{
    khm_int32 rv;

    EnterCriticalSection(&c->cs);
    if(c->n_prompts <= idx ||
       c->prompts == NULL) {

        rv = KHM_ERROR_OUT_OF_BOUNDS;
        *prompt = NULL;
    } else {

        *prompt = c->prompts[idx];
        rv = KHM_ERROR_SUCCESS;
    }
    LeaveCriticalSection(&c->cs);

    return rv;
}

void
khuiint_trim_str(wchar_t * s, khm_size cch) {
    wchar_t * c, * last_ws;

    for (c = s; *c && iswspace(*c) && ((khm_size)(c - s)) < cch; c++);

    if (((khm_size)(c - s)) >= cch)
        return;

    if (c != s && ((khm_size)(c - s)) < cch) {
#if _MSC_VER >= 1400 && __STDC_WANT_SECURE_LIB__
        wmemmove_s(s, cch, c, cch - ((khm_size)(c - s)));
#else
        memmove(s, c, (cch - ((khm_size)(c - s)))* sizeof(wchar_t));
#endif
    }

    last_ws = NULL;
    for (c = s; *c && ((khm_size)(c - s)) < cch; c++) {
        if (!iswspace(*c))
            last_ws = NULL;
        else if (last_ws == NULL)
            last_ws = c;
    }

    if (last_ws)
        *last_ws = L'\0';
}

KHMEXP khm_int32 KHMAPI 
khui_cw_sync_prompt_values(khui_new_creds * c)
{
    khm_size i;
    khm_size n;
    HWND hw;
    wchar_t tmpbuf[KHUI_MAXCCH_PROMPT_VALUE];

    EnterCriticalSection(&c->cs);
 redo_loop:
    n = c->n_prompts;
    for(i=0; i<n; i++) {
        khui_new_creds_prompt * p;

        p = c->prompts[i];
        if(p->hwnd_edit) {
            hw = p->hwnd_edit;
            LeaveCriticalSection(&c->cs);

            GetWindowText(hw, tmpbuf, ARRAYLENGTH(tmpbuf));
            khuiint_trim_str(tmpbuf, ARRAYLENGTH(tmpbuf));

            EnterCriticalSection(&c->cs);
            if (n != c->n_prompts)
                goto redo_loop;
            SecureZeroMemory(p->value, KHUI_MAXCB_PROMPT_VALUE);
            StringCchCopy(p->value, KHUI_MAXCCH_PROMPT_VALUE,
                          tmpbuf);
        }
    }
    LeaveCriticalSection(&c->cs);

    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32 KHMAPI 
khui_cw_get_prompt_value(khui_new_creds * c, 
                         khm_size idx, 
                         wchar_t * buf, 
                         khm_size *cbbuf)
{
    khui_new_creds_prompt * p;
    khm_int32 rv;
    size_t cb;

    rv = khui_cw_get_prompt(c, idx, &p);
    if(KHM_FAILED(rv))
        return rv;

    EnterCriticalSection(&c->cs);

    if(FAILED(StringCbLength(p->value, KHUI_MAXCB_PROMPT_VALUE, &cb))) {
        *cbbuf = 0;
        if(buf != NULL)
            *buf = 0;
        LeaveCriticalSection(&c->cs);
        return KHM_ERROR_SUCCESS;
    }
    cb += sizeof(wchar_t);

    if(buf == NULL || *cbbuf < cb) {
        *cbbuf = cb;
        LeaveCriticalSection(&c->cs);
        return KHM_ERROR_TOO_LONG;
    }

    StringCbCopy(buf, *cbbuf, p->value);
    *cbbuf = cb;
    LeaveCriticalSection(&c->cs);

    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32 KHMAPI 
khui_cw_set_response(khui_new_creds * c, 
                     khm_int32 type, 
                     khm_int32 response)
{
    khui_new_creds_by_type * t = NULL;
    EnterCriticalSection(&c->cs);
    khui_cw_find_type(c, type, &t);
    c->response |= response & KHUI_NCMASK_RESPONSE;
    if(t) {
        t->flags &= ~KHUI_NCMASK_RESULT;
        t->flags |= (response & KHUI_NCMASK_RESULT);

        if (!(response & KHUI_NC_RESPONSE_NOEXIT) &&
            !(response & KHUI_NC_RESPONSE_PENDING))
            t->flags |= KHUI_NC_RESPONSE_COMPLETED;
    }
    LeaveCriticalSection(&c->cs);
    return KHM_ERROR_SUCCESS;
}

/* only called from a identity provider callback */
KHMEXP khm_int32 KHMAPI
khui_cw_add_control_row(khui_new_creds * c,
                        HWND label,
                        HWND input,
                        khui_control_size size)
{
    if (c && c->hwnd) {
        khui_control_row row;

        row.label = label;
        row.input = input;
        row.size = size;

        SendMessage(c->hwnd,
                    KHUI_WM_NC_NOTIFY,
                    MAKEWPARAM(0, WMNC_ADD_CONTROL_ROW),
                    (LPARAM) &row);

        return KHM_ERROR_SUCCESS;
    } else {
        return KHM_ERROR_INVALID_PARAM;
    }
}
