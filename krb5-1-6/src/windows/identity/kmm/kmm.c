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

#include<kmminternal.h>
#include<assert.h>

khm_boolean kmmint_load_locale_lib(kmm_module_i * m, kmm_module_locale * l)
{
    HMODULE h;

    if(l->filename != NULL) {
        wchar_t path[MAX_PATH];
        DWORD dw;

        /* construct the path name */
        assert(m->h_module != NULL);

        dw = PathIsFileSpec(l->filename);

        assert(dw);
        if (!dw)
            return FALSE;

        dw = GetModuleFileName(m->h_module, path, ARRAYLENGTH(path));
        assert(dw != 0);
        if (dw == 0)
            return FALSE;

        PathRemoveFileSpec(path);
        dw = PathAppend(path, l->filename);
        assert(dw);
        if (!dw)
            return FALSE;

        h = LoadLibrary(path);
        if(!h)
            return FALSE;

        EnterCriticalSection(&cs_kmm);
        m->h_resource = h;
        m->lcid_resource = (WORD) l->language;
        LeaveCriticalSection(&cs_kmm);

        return TRUE;

    } else {
        /*  in this case, the language resources are assumed to be in the
            main module library itself. */

        EnterCriticalSection(&cs_kmm);
        m->h_resource = m->h_module;
        m->lcid_resource = (WORD) l->language;
        LeaveCriticalSection(&cs_kmm);

        return TRUE;
    }
}


KHMEXP khm_int32 KHMAPI kmm_set_locale_info(kmm_module module, kmm_module_locale * locales, khm_int32 n_locales)
{
    kmm_module_i * m;
    LANGID lcid;
    int i;
    int * f;
    khm_int32 rv = KHM_ERROR_SUCCESS;

    m = kmm_module_from_handle(module);

    if(!m || m->state != KMM_MODULE_STATE_INIT)
        return KHM_ERROR_INVALID_OPERATION;

    if(!locales || n_locales < 0)
        return KHM_ERROR_INVALID_PARAM;

    f = PMALLOC(n_locales * sizeof(int));
    if(!f)
        return KHM_ERROR_UNKNOWN;
    ZeroMemory(f, sizeof(int) * n_locales);

    lcid = GetUserDefaultLangID();

    /* first search for an exact match */
    for(i=0; i<n_locales; i++) {
        if(locales[i].language == lcid) {
            f[i] = TRUE;
            if(kmmint_load_locale_lib(m, &locales[i]))
                break;
        }
    }

    if(i<n_locales)
        goto _exit;

    /* ok, that didn't work.  Try an inexact match. */
    for(i=0; i<n_locales; i++) {
        if(!f[i] && (PRIMARYLANGID(locales[i].language) == PRIMARYLANGID(lcid))) {
            f[i] = TRUE;
            if(kmmint_load_locale_lib(m,&locales[i]))
                break;
        }
    }

    if(i < n_locales)
        goto _exit;

    /* hmm. no matches yet. just try to locate the default locale */
    for(i=0; i<n_locales; i++) {
        if(!f[i] && (locales[i].flags & KMM_MLOC_FLAG_DEFAULT)) {
            f[i] = TRUE;
            if(kmmint_load_locale_lib(m,&locales[i]))
                break;
        }
    }

    if(i < n_locales)
        goto _exit;

    /* give up */
    rv = KHM_ERROR_NOT_FOUND;

_exit:
    PFREE(f);
    return rv;
}

#ifdef _WIN32
KHMEXP HMODULE     KHMAPI kmm_get_resource_hmodule(kmm_module vm)
{
    if(!kmm_is_module(vm))
        return NULL;
    else
        return (kmm_module_from_handle(vm))->h_resource;
}
#endif

KHMEXP kmm_module KHMAPI
kmm_this_module(void) {
    kmm_plugin_i * p;
    kmm_module_i * m;
    kmm_module vm;

    p = TlsGetValue(tls_kmm);
    if (!kmm_is_plugin(p))
        return NULL;

    m = p->module;
    vm = kmm_handle_from_module(m);

    kmm_hold_module(vm);

    return vm;
}

KHMEXP kmm_plugin KHMAPI
kmm_this_plugin(void) {
    kmm_plugin_i * p;
    kmm_plugin vp;

    p = TlsGetValue(tls_kmm);
    if (!kmm_is_plugin(p))
        return NULL;

    vp = kmm_handle_from_plugin(p);

    kmm_hold_plugin(vp);

    return vp;
}
