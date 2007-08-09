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
#include<netidmgr_version.h>
#include<assert.h>

/* should only be accessed from the registrar thread */
khm_size kmm_active_modules = 0;

kmm_module_i * kmmint_get_module_i(wchar_t * name)
{
    kmm_module_i * m;
    size_t sz;

    if(FAILED(StringCbLength(name, KMM_MAXCB_NAME, &sz)))
        return NULL;
    sz += sizeof(wchar_t);

    EnterCriticalSection(&cs_kmm);
    m = (kmm_module_i *) hash_lookup(hash_modules, (void *) name);

    if(m == NULL) {
        m = PMALLOC(sizeof(kmm_module_i));
        ZeroMemory(m, sizeof(kmm_module_i));

        m->magic = KMM_MODULE_MAGIC;
        m->name = PMALLOC(sz);
        StringCbCopy(m->name, sz, name);
        m->state = KMM_MODULE_STATE_NONE;

        hash_add(hash_modules, (void *) m->name, (void *) m);
        LPUSH(&kmm_all_modules, m);
    }
    LeaveCriticalSection(&cs_kmm);

    return m;
}

kmm_module_i * kmmint_find_module_i(wchar_t * name)
{
    kmm_module_i * m;

    EnterCriticalSection(&cs_kmm);
    m = (kmm_module_i *) hash_lookup(hash_modules, (void *) name);
    LeaveCriticalSection(&cs_kmm);

    return m;
}

/* called with cs_kmm held */
void kmmint_free_module(kmm_module_i * m)
{
    m->magic = 0;

    hash_del(hash_modules, m->name);
    LDELETE(&kmm_all_modules, m);

    if (m->name)
        PFREE(m->name);

    if (m->description)
        PFREE(m->description);

    if (m->path)
        PFREE(m->path);

    if (m->vendor)
        PFREE(m->vendor);

    if (m->support)
        PFREE(m->support);

    if (m->version_info)
        PFREE(m->version_info);

    PFREE(m);
}

KHMEXP khm_int32   KHMAPI kmm_hold_module(kmm_module module)
{
    if(!kmm_is_module(module))
        return KHM_ERROR_INVALID_PARAM;
    EnterCriticalSection(&cs_kmm);
    kmm_module_from_handle(module)->refcount++;
    LeaveCriticalSection(&cs_kmm);

    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32   KHMAPI kmm_release_module(kmm_module vm)
{
    kmm_module_i * m;

    if(!kmm_is_module(vm))
        return KHM_ERROR_INVALID_PARAM;

    EnterCriticalSection(&cs_kmm);
    m = kmm_module_from_handle(vm);
    if(! --(m->refcount)) 
    {
        /* note that a 0 ref count means that there are no active
           plugins */
        kmmint_free_module(m);
    }
    LeaveCriticalSection(&cs_kmm);
    return KHM_ERROR_SUCCESS;
}

khm_int32
kmmint_check_api_version(DWORD v) {
    /* for now, we allow API versions in the range
       KH_VERSION_API_MINCOMPAT through KH_VERSION_API, inclusive.  In
       the future when we are swamped with so much time that we don't
       know what to do with it, we can actually parse the
       apiversion.txt file and create a compatibility table which we
       can check against the functions used by the module and decide
       whether or not it is compatible. */

    if (v < KH_VERSION_API_MINCOMPAT ||
        v > KH_VERSION_API)
        return KHM_ERROR_INCOMPATIBLE;
    else
        return KHM_ERROR_SUCCESS;
}

struct lang_code {
    WORD language;
    WORD codepage;
};

khm_int32
kmmint_read_module_info(kmm_module_i * m) {
    /* the only fields we can count on at this point are m->name and
       m->path */
    DWORD t;
    size_t cb;
    WORD lang;
    khm_int32 rv = KHM_ERROR_SUCCESS;
    struct lang_code *languages;
    int n_languages;
    int i;
    wchar_t resname[256];       /* the resource names are a lot shorter */
    wchar_t * r;
    VS_FIXEDFILEINFO *vff;

    assert(m->name);
    assert(m->path);

    t = TRUE;
    cb = GetFileVersionInfoSize(m->path,
                                &t);
    /* if successful, cb gets the size in bytes of the version info
       structure and sets t to zero */
    if (t) {
        return KHM_ERROR_NOT_FOUND;
    } else if (cb == 0) {
        _report_mr1(KHERR_WARNING, MSG_RMI_NOT_FOUND, _dupstr(m->path));
        return KHM_ERROR_INVALID_PARAM;
    }

    if (m->version_info) {
        PFREE(m->version_info);
        m->version_info = NULL;
    }

    m->version_info = PMALLOC(cb);
#ifdef DEBUG
    assert(m->version_info);
#endif

    if(!GetFileVersionInfo(m->path,
                           t, (DWORD) cb, m->version_info)) {
        rv = KHM_ERROR_NOT_FOUND;
        _report_mr1(KHERR_WARNING, MSG_RMI_NOT_FOUND, _dupstr(m->path));
        _location(L"GetFileVersionInfo");
        goto _cleanup;
    }

    if(!VerQueryValue(m->version_info,
                     L"\\VarFileInfo\\Translation",
                     (LPVOID*) &languages,
                     &cb)) {
        rv = KHM_ERROR_INVALID_PARAM;
        _report_mr1(KHERR_WARNING, MSG_RMI_NO_TRANS, _dupstr(m->path));
        _location(L"VerQueryValue");
        goto _cleanup;
    }

    n_languages = (int) (cb / sizeof(*languages));

    /* Try searching for the user's default language first */
    lang = GetUserDefaultLangID();
    for (i = 0; i < n_languages; i++) {
        if(languages[i].language == lang)
            break;
    }

    /* If not, try the system default */
    if (i >= n_languages) {
        lang = GetSystemDefaultLangID();
        for (i=0; i<n_languages; i++)
            if (languages[i].language == lang)
                break;
    }

    /* Then try EN_US */
    if (i >= n_languages) {
        lang = MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US);
        for (i=0; i<n_languages; i++)
            if (languages[i].language == lang)
                break;
    }

    /* Language neutral? */
    if (i >= n_languages) {
        lang = MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL);
        for (i=0; i<n_languages; i++)
            if (languages[i].language == lang)
                break;
    }

    /* Just use the first one? */
    if (i >= n_languages) {
        i = 0;
    }

    if (i >= n_languages) {
        rv = KHM_ERROR_INVALID_PARAM;
        _report_mr0(KHERR_WARNING, MSG_RMI_NO_LOCAL);
        goto _cleanup;
    }

    /* check module name */
    StringCbPrintf(resname, sizeof(resname),
                   L"\\StringFileInfo\\%04x%04x\\" TEXT(NIMV_MODULE),
                   languages[i].language,
                   languages[i].codepage);

    if (!VerQueryValue(m->version_info,
                       resname, (LPVOID *) &r, &cb)) {
        rv = KHM_ERROR_INVALID_PARAM;
        _report_mr1(KHERR_WARNING, MSG_RMI_RES_MISSING, 
                    _cstr(TEXT(NIMV_MODULE)));
        goto _cleanup;
    }

    if (cb > KMM_MAXCB_NAME ||
        FAILED(StringCbLength(r, KMM_MAXCB_NAME, &cb))) {
        rv = KHM_ERROR_INVALID_PARAM;
        _report_mr1(KHERR_WARNING, MSG_RMI_RES_TOO_LONG,
                    _cstr(TEXT(NIMV_MODULE)));
        goto _cleanup;
    }

    if (wcscmp(r, m->name)) {
        rv = KHM_ERROR_INVALID_PARAM;
        _report_mr2(KHERR_WARNING, MSG_RMI_MOD_MISMATCH,
                    _dupstr(r), _dupstr(m->name));
        goto _cleanup;
    }

    /* check API version */
    StringCbPrintf(resname, sizeof(resname),
                   L"\\StringFileInfo\\%04x%04x\\" TEXT(NIMV_APIVER),
                   languages[i].language,
                   languages[i].codepage);

    if (!VerQueryValue(m->version_info,
                       resname, (LPVOID *) &r, &cb)) {
        rv = KHM_ERROR_INVALID_PARAM;
        _report_mr1(KHERR_WARNING, MSG_RMI_RES_MISSING, 
                    _cstr(TEXT(NIMV_APIVER)));
        goto _cleanup;
    }

    if (cb > KMM_MAXCB_NAME ||
        FAILED(StringCbLength(r, KMM_MAXCB_NAME, &cb))) {
        rv = KHM_ERROR_INVALID_PARAM;
        _report_mr1(KHERR_WARNING, MSG_RMI_RES_TOO_LONG,
                    _cstr(TEXT(NIMV_APIVER)));
        goto _cleanup;
    }

    t = wcstol(r, NULL, 10);

    rv = kmmint_check_api_version(t);

    if (KHM_FAILED(rv)) {
        _report_mr2(KHERR_WARNING, MSG_RMI_API_MISMATCH,
                    _int32(t), _int32(KH_VERSION_API));
        goto _cleanup;
    }

    /* Looks good.  Now load the description, copyright, support URI
       and file versions */
    if (m->description) {
        PFREE(m->description);
        m->description = NULL;
    }

    StringCbPrintf(resname, sizeof(resname),
                   L"\\StringFileInfo\\%04x%04x\\FileDescription",
                   languages[i].language,
                   languages[i].codepage);

    if (!VerQueryValue(m->version_info,
                       resname, (LPVOID *) &r, &cb)) {
        rv = KHM_ERROR_INVALID_PARAM;
        _report_mr1(KHERR_WARNING, MSG_RMI_RES_MISSING, 
                    _cstr(L"FileDescription"));
        goto _cleanup;
    }

    if (cb > KMM_MAXCB_DESC ||
        FAILED(StringCbLength(r, KMM_MAXCB_DESC, &cb))) {
        rv = KHM_ERROR_INVALID_PARAM;
        _report_mr1(KHERR_WARNING, MSG_RMI_RES_TOO_LONG,
                    _cstr(L"FileDescription"));
        goto _cleanup;
    }

    cb += sizeof(wchar_t);

    m->description = PMALLOC(cb);
#ifdef DEBUG
    assert(m->description);
#endif
    StringCbCopy(m->description, cb, r);

    /* on to the support URI */
    if (m->support) {
        PFREE(m->support);
        m->support = NULL;
    }

    StringCbPrintf(resname, sizeof(resname),
                   L"\\StringFileInfo\\%04x%04x\\" TEXT(NIMV_SUPPORT),
                   languages[i].language,
                   languages[i].codepage);

    if (!VerQueryValue(m->version_info,
                       resname, (LPVOID *) &r, &cb)) {
        rv = KHM_ERROR_INVALID_PARAM;
        _report_mr1(KHERR_WARNING, MSG_RMI_RES_MISSING,
                    _cstr(TEXT(NIMV_SUPPORT)));
        goto _cleanup;
    }

    if (cb > KMM_MAXCB_SUPPORT ||
        FAILED(StringCbLength(r, KMM_MAXCB_SUPPORT, &cb))) {
        rv = KHM_ERROR_INVALID_PARAM;
        _report_mr1(KHERR_WARNING, MSG_RMI_RES_TOO_LONG,
                    _cstr(TEXT(NIMV_SUPPORT)));
        goto _cleanup;
    }

    cb += sizeof(wchar_t);

    m->support = PMALLOC(cb);
#ifdef DEBUG
    assert(m->support);
#endif
    StringCbCopy(m->support, cb, r);

    /* the vendor/copyright */
    if (m->vendor) {
        PFREE(m->vendor);
        m->vendor = NULL;
    }

    StringCbPrintf(resname, sizeof(resname),
                   L"\\StringFileInfo\\%04x%04x\\LegalCopyright",
                   languages[i].language,
                   languages[i].codepage);

    if (!VerQueryValue(m->version_info,
                       resname, (LPVOID *) &r, &cb)) {
        rv = KHM_ERROR_INVALID_PARAM;
        _report_mr1(KHERR_WARNING, MSG_RMI_RES_MISSING, 
                    _cstr(L"LegalCopyright"));
        goto _cleanup;
    }

    if (cb > KMM_MAXCB_SUPPORT ||
        FAILED(StringCbLength(r, KMM_MAXCB_SUPPORT, &cb))) {
        rv = KHM_ERROR_INVALID_PARAM;
        _report_mr1(KHERR_WARNING, MSG_RMI_RES_TOO_LONG,
                    _cstr(L"LegalCopyright"));
        goto _cleanup;
    }

    cb += sizeof(wchar_t);

    m->vendor = PMALLOC(cb);
#ifdef DEBUG
    assert(m->vendor);
#endif
    StringCbCopy(m->vendor, cb, r);

    if (!VerQueryValue(m->version_info,
                       L"\\",
                       (LPVOID *) &vff,
                       &cb) ||
        cb != sizeof(*vff)) {

        rv = KHM_ERROR_INVALID_PARAM;
        _report_mr1(KHERR_WARNING, MSG_RMI_RES_MISSING, 
                    _cstr(L"Fixed Version Info"));
        goto _cleanup;
    }

    m->file_version.major = HIWORD(vff->dwFileVersionMS);
    m->file_version.minor = LOWORD(vff->dwFileVersionMS);
    m->file_version.patch = HIWORD(vff->dwFileVersionLS);
    m->file_version.aux   = LOWORD(vff->dwFileVersionLS);

    m->prod_version.major = HIWORD(vff->dwProductVersionMS);
    m->prod_version.minor = LOWORD(vff->dwProductVersionMS);
    m->prod_version.patch = HIWORD(vff->dwProductVersionLS);
    m->prod_version.aux   = LOWORD(vff->dwProductVersionLS);

    rv = KHM_ERROR_SUCCESS;

 _cleanup:
    if (KHM_FAILED(rv)) {
        if (m->version_info) {
            PFREE(m->version_info);
            m->version_info = NULL;
        }
    }

    return rv;
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
        return KHM_ERROR_INVALID_PARAM;
    cbsize += sizeof(wchar_t);

    EnterCriticalSection(&cs_kmm);
    mi = kmmint_find_module_i(modname);

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
        m = kmmint_get_module_i(modname);
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

KHMEXP khm_int32   KHMAPI 
kmm_get_module_state(kmm_module m)
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
        rv = KHM_ERROR_INVALID_PARAM;
    else {
        m = kmm_module_from_handle(vm);

        ZeroMemory(info, sizeof(*info));

        info->reg.name = m->name;
        info->reg.path = m->path;
        info->reg.vendor = m->vendor;

        info->reg.n_plugins = m->plugin_count;

        info->state = m->state;

        info->h_module = vm;

        info->file_version = m->file_version;
        info->product_version = m->prod_version;
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


KHMEXP khm_int32   KHMAPI 
kmm_unload_module(kmm_module module) {

    if(!kmm_is_module(module))
        return KHM_ERROR_INVALID_PARAM;

    kmm_hold_module(module);
    kmq_post_message(KMSG_KMM, 
		     KMSG_KMM_I_REG, 
		     KMM_REG_EXIT_MODULE, 
		     (void *) kmm_module_from_handle(module));

    return KHM_ERROR_SUCCESS;
}

KHMEXP khm_int32   KHMAPI 
kmm_load_default_modules(void) {
    khm_handle csm = NULL;
    khm_handle cs_mod = NULL;
    khm_int32 rv;
    wchar_t buf[KMM_MAXCCH_NAME];
    khm_size s;

    rv = kmm_get_modules_config(0, &csm);
    if(KHM_FAILED(rv))
        return rv;

    _begin_task(KHERR_CF_TRANSITIVE);
    _report_mr0(KHERR_NONE, MSG_LOAD_DEFAULT);
    _describe();

    kmmint_add_to_module_queue();

    while(KHM_SUCCEEDED(khc_enum_subspaces(csm, cs_mod, &cs_mod))) {

        s = sizeof(buf);
        if (KHM_FAILED(khc_get_config_space_name(cs_mod, buf, &s)))
            continue;

        /* check for schema subspace.  This is not an actual module. */
        if (!wcscmp(buf, L"_Schema"))
            continue;

        kmm_load_module(buf, 0, NULL);
    }

    kmmint_remove_from_module_queue();

    if(csm)
        khc_close_space(csm);

    _end_task();

    return rv;
}

#ifdef _WIN32
KHMEXP HMODULE     KHMAPI 
kmm_get_hmodule(kmm_module m)
{
    if(!kmm_is_module(m))
        return NULL;
    else
        return kmm_module_from_handle(m)->h_module;
}
#endif
