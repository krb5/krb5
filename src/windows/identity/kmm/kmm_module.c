/*
 * Copyright (c) 2004 Massachusetts Institute of Technology
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

#include<kmminternal.h>

kmm_module_i * kmm_get_module_i(wchar_t * name)
{
    kmm_module_i * m;
    size_t sz;

    if(FAILED(StringCbLength(name, KMM_MAXCB_NAME, &sz)))
        return NULL;
    sz += sizeof(wchar_t);

    EnterCriticalSection(&cs_kmm);
    m = (kmm_module_i *) hash_lookup(hash_modules, (void *) name);

    if(m == NULL) {
        m = malloc(sizeof(kmm_module_i));
        ZeroMemory(m, sizeof(kmm_module_i));

        m->magic = KMM_MODULE_MAGIC;
        m->name = malloc(sz);
        StringCbCopy(m->name, sz, name);
        m->state = KMM_MODULE_STATE_NONE;

        hash_add(hash_modules, (void *) m->name, (void *) m);
        LPUSH(&kmm_all_modules, m);
    }
    LeaveCriticalSection(&cs_kmm);

    return m;
}

kmm_module_i * kmm_find_module_i(wchar_t * name)
{
    kmm_module_i * m;

    EnterCriticalSection(&cs_kmm);
    m = (kmm_module_i *) hash_lookup(hash_modules, (void *) name);
    LeaveCriticalSection(&cs_kmm);

    return m;
}

/* called with cs_kmm held */
void kmm_free_module(kmm_module_i * m)
{
    m->magic = 0;

    hash_del(hash_modules, m->name);
    LDELETE(&kmm_all_modules, m);

    if (m->name)
        free(m->name);
    if (m->path)
        free(m->path);
    if (m->vendor)
        free(m->vendor);
    if (m->version_info)
        free(m->version_info);
    free(m);

    if (kmm_all_modules == NULL)
        SetEvent(evt_exit);
}

KHMEXP khm_int32   KHMAPI kmm_hold_module(kmm_module module)
{
    if(!kmm_is_module(module))
        return KHM_ERROR_INVALID_PARM;
    EnterCriticalSection(&cs_kmm);
    kmm_module_from_handle(module)->refcount++;
    LeaveCriticalSection(&cs_kmm);

    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32   KHMAPI kmm_release_module(kmm_module vm)
{
    kmm_module_i * m;
    if(!kmm_is_module(vm))
        return KHM_ERROR_INVALID_PARM;

    EnterCriticalSection(&cs_kmm);
    m = kmm_module_from_handle(vm);
    if(! --(m->refcount)) 
    {
        /* note that a 0 ref count means that there are no active
           plugins */
        kmm_free_module(m);
    }
    LeaveCriticalSection(&cs_kmm);
    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32   KHMAPI kmm_load_module(wchar_t * modname, 
                                          khm_int32 flags, 
                                          kmm_module * result)
{
    kmm_module_i * m = NULL;
    kmm_module_i * mi;
    size_t cbsize;
    khm_int32 rv = KHM_ERROR_SUCCESS;

    if(FAILED(StringCbLength(modname, KMM_MAXCB_NAME, &cbsize)))
        return KHM_ERROR_INVALID_PARM;
    cbsize += sizeof(wchar_t);

    EnterCriticalSection(&cs_kmm);
    mi = kmm_find_module_i(modname);

    if(mi != NULL) {
        kmm_hold_module(kmm_handle_from_module(mi));
        /* check if the module has either failed to load either or if
        it has been terminated.  If so, we try once again to load the
        module. */
        if(!(flags & KMM_LM_FLAG_NOLOAD) && 
            (mi->state < 0 || mi->state == KMM_MODULE_STATE_EXITED)) 
        {
            mi->state = KMM_MODULE_STATE_PREINIT;
        }
    }
    LeaveCriticalSection(&cs_kmm);

    if(flags & KMM_LM_FLAG_NOLOAD) {
        if(result)
            *result = mi;
        else if(mi)
            kmm_release_module(kmm_handle_from_module(mi));

        return (mi)? KHM_ERROR_SUCCESS: KHM_ERROR_NOT_FOUND;
    }

    if(mi) {
        m = mi;
    } else {
        m = kmm_get_module_i(modname);
        m->state = KMM_MODULE_STATE_PREINIT;
        kmm_hold_module(kmm_handle_from_module(m));
    }

    /* the module is already running or is already being
       worked on by the registrar */
    if(m->state != KMM_MODULE_STATE_PREINIT) {
        if(result)
            *result = kmm_handle_from_module(m);
        else
            kmm_release_module(kmm_handle_from_module(m));

        return KHM_ERROR_EXISTS;
    }

    kmmint_add_to_module_queue();

    if(flags & KMM_LM_FLAG_SYNC) {
        kmm_hold_module(kmm_handle_from_module(m));
        kmq_send_message(KMSG_KMM, 
                         KMSG_KMM_I_REG, 
                         KMM_REG_INIT_MODULE, 
                         (void*) m);
        if(m->state <= 0) {
            /* failed to load ? */
            if(m->state == KMM_MODULE_STATE_FAIL_NOT_FOUND)
                rv = KHM_ERROR_NOT_FOUND;
            else if(m->state == KMM_MODULE_STATE_FAIL_SIGNATURE)
                rv = KHM_ERROR_INVALID_SIGNATURE;
            else
                rv = KHM_ERROR_UNKNOWN;

            kmm_release_module(kmm_handle_from_module(m));
            if(result)
                *result = NULL;
        } else {
            if(result)
                *result = kmm_handle_from_module(m);
            else
                kmm_release_module(kmm_handle_from_module(m));
        }
    } else {
        kmm_hold_module(kmm_handle_from_module(m));
        kmq_post_message(KMSG_KMM, 
                         KMSG_KMM_I_REG, 
                         KMM_REG_INIT_MODULE, 
                         (void*) m);
        if(result)
            *result = kmm_handle_from_module(m);
        else
            kmm_release_module(kmm_handle_from_module(m));
    }

    return rv;
}

KHMEXP khm_int32   KHMAPI kmm_get_module_state(kmm_module m)
{
    if(!kmm_is_module(m))
        return KMM_MODULE_STATE_NONE;
    else
        return kmm_module_from_handle(m)->state;
}

KHMEXP khm_int32   KHMAPI
kmm_get_module_info_i(kmm_module vm, kmm_module_info * info) {
    kmm_module_i * m;
    khm_int32 rv;

    EnterCriticalSection(&cs_kmm);
    if (!kmm_is_module(vm) || !info)
        rv = KHM_ERROR_INVALID_PARM;
    else {
        m = kmm_module_from_handle(vm);

        ZeroMemory(info, sizeof(*info));

        info->reg.name = m->name;
        info->reg.path = m->path;
        info->reg.vendor = m->vendor;

        info->reg.n_plugins = m->plugin_count;

        info->state = m->state;

        info->h_module = vm;
        kmm_hold_module(vm);

        rv = KHM_ERROR_SUCCESS;
    }
    LeaveCriticalSection(&cs_kmm);

    return rv;
}

KHMEXP khm_int32   KHMAPI
kmm_release_module_info_i(kmm_module_info * info) {
    if (info->h_module)
        kmm_release_module(info->h_module);

    ZeroMemory(info, sizeof(*info));

    return KHM_ERROR_SUCCESS;
}


KHMEXP khm_int32   KHMAPI kmm_unload_module(kmm_module module)
{
    if(!kmm_is_module(module))
        return KHM_ERROR_INVALID_PARM;

    kmm_hold_module(module);
    kmq_post_message(KMSG_KMM, 
		     KMSG_KMM_I_REG, 
		     KMM_REG_EXIT_MODULE, 
		     (void *) kmm_module_from_handle(module));

    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32   KHMAPI kmm_load_default_modules(void) {
    khm_handle csm = NULL;
    khm_int32 rv;
    wchar_t * ll = NULL;
    wchar_t *str;
    wchar_t buf[KMM_MAXCCH_NAME];
    khm_size s;

    rv = kmm_get_modules_config(0, &csm);
    if(KHM_FAILED(rv))
        return rv;

    _begin_task(KHERR_CF_TRANSITIVE);
    _report_mr0(KHERR_NONE, MSG_LOAD_DEFAULT);
    _describe();

    rv = khc_read_multi_string(csm, KMM_VALNAME_LOADLIST, NULL, &s);
    if(rv != KHM_ERROR_TOO_LONG)
        goto _exit;

    ll = malloc(s);
    rv = khc_read_multi_string(csm, KMM_VALNAME_LOADLIST, ll, &s);
    if(KHM_FAILED(rv))
        goto _exit;

    kmmint_add_to_module_queue();

    str = ll;
    while(str && *str) {
        if(SUCCEEDED(StringCbCopy(buf, sizeof(buf), str))) {
            kmm_load_module(buf, 0, NULL);
        }
        str = multi_string_next(str);
    }

    kmmint_remove_from_module_queue();

_exit:
    if(ll)
        free(ll);
    if(csm)
        khc_close_space(csm);

    _end_task();

    return rv;
}

#ifdef _WIN32
KHMEXP HMODULE     KHMAPI kmm_get_hmodule(kmm_module m)
{
    if(!kmm_is_module(m))
        return NULL;
    else
        return kmm_module_from_handle(m)->h_module;
}
#endif
